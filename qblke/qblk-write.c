#include "qblk.h"

/* Finish persist work on rb.
 * Free persist_work
 */
void qblk_end_persist_point(struct qblk_rb *rb,
							struct qblk *qblk,
							struct qblk_persist_work *persist_work)
{
	int nr_rb = qblk->nr_queues;
	unsigned int rb_index = rb->rb_index;

	lockdep_assert_held(&rb->s_lock);

	spin_lock(&persist_work->lock);
	set_bit(rb_index, persist_work->persist_bm);
	//pr_notice("%s, rb[%d]\n", __func__, rb_index);

	if (find_first_zero_bit(persist_work->persist_bm, nr_rb) == nr_rb) {
		struct request *req = persist_work->req;

		spin_unlock(&persist_work->lock);
		blk_mq_end_request(req, BLK_STS_OK);
		qblk_printTimeMonotonic(__func__, __LINE__);
		qblk_persist_work_release(persist_work);
	} else {
		spin_unlock(&persist_work->lock);
	}

}

static inline void qblk_finish_PREFLUSH_FUA_in_rb(struct qblk *qblk,
					struct qblk_w_ctx *w_ctx,
					struct qblk_rb *rb,
					int pos)
{
	struct request *req = w_ctx->fua_req;
	struct qblk_per_rb_pw *pw, *tmp;

	lockdep_assert_held(&rb->s_lock);

	list_for_each_entry_safe(pw, tmp, &w_ctx->persist_list, list) {
		list_del(&pw->list);
		qblk_end_persist_point(rb, qblk, pw->pw);
	}

	if (req) {
		blk_mq_end_request(req, BLK_STS_OK);
		qblk_printTimeMonotonic(__func__, __LINE__);
		w_ctx->fua_req = NULL;
	}

}

static unsigned long qblk_end_w_bio(struct qblk *qblk,
				struct nvm_rq *rqd,
				struct qblk_c_ctx *c_ctx)
{
	struct qblk_rb *ringBuffer = qblk_get_rb_by_cpuid(qblk, c_ctx->rb_count);
	unsigned long ret;
	int i;

	//pr_notice("%s, cc[%d]\n", __func__, c_ctx->nr_valid);
	lockdep_assert_held(&ringBuffer->s_lock);

	for (i = 0; i < c_ctx->nr_valid; i++) {
		struct qblk_w_ctx *w_ctx;
		int pos = c_ctx->sentry + i;

		w_ctx = qblk_rb_w_ctx(qblk, ringBuffer,
			qblk_rb_wrap_pos(ringBuffer, pos));

		qblk_finish_PREFLUSH_FUA_in_rb(qblk, w_ctx, ringBuffer, pos);
	}

	if (c_ctx->nr_padded)
		qblk_bio_free_pages(qblk, rqd->bio, c_ctx->nr_valid,
							c_ctx->nr_padded);

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(rqd->nr_ppas, &qblk->sync_writes);
#endif

	ret = qblk_rb_sync_advance(qblk, ringBuffer, c_ctx->nr_valid);
	qblk_per_rb_account(qblk, c_ctx->rb_count, QBLK_RB_SYNCED, c_ctx->nr_valid);

	bio_put(rqd->bio);
	qblk_percpu_dma_free(qblk, c_ctx->cpuid, rqd->meta_list, rqd->dma_meta_list);
	qblk_free_rqd(qblk, rqd, QBLK_WRITE);

	return ret;
}

static unsigned long qblk_end_queued_w_bio(struct qblk *qblk,
					   struct nvm_rq *rqd,
					   struct qblk_c_ctx *c_ctx)
{
	//pr_notice("%s\n",__func__);
	list_del(&c_ctx->list);
	return qblk_end_w_bio(qblk, rqd, c_ctx);
}
				   
static int qblk_calc_secs_to_sync(struct qblk *qblk,
				unsigned int secs_avail,
				unsigned int secs_to_flush)
{
	int secs_to_sync;

	secs_to_sync = qblk_calc_secs(qblk, secs_avail, secs_to_flush);

#ifdef CONFIG_NVM_DEBUG
	if ((!secs_to_sync && secs_to_flush)
			|| (secs_to_sync < 0)
			|| (secs_to_sync > secs_avail && !secs_to_flush)) {
		pr_err("qblk: bad sector calculation (a:%d,s:%d,f:%d)\n",
				secs_avail, secs_to_sync, secs_to_flush);
	}
#endif

	return secs_to_sync;
}

#ifdef QBLKE_FUNCLATENCY
QBLKE_SHOULD_INLINE struct ch_info * qblk_writeback_channel(struct qblk *qblk,
			struct qblk_queue *pq)
#else
static inline struct ch_info * qblk_writeback_channel(struct qblk *qblk,
			struct qblk_queue *pq)
#endif
{
	//return &qblk->ch[0];
#if 0
	int nr_ch;

	nr_ch = READ_ONCE(pq->wbchnl);
	if (nr_ch == qblk->nr_channels-1)
		WRITE_ONCE(pq->wbchnl, 0);
	else
		WRITE_ONCE(pq->wbchnl, nr_ch+1);
	return &qblk->ch[nr_ch];
#endif

#if 1
	int nr_ch;

	nr_ch = (atomic_inc_return(&qblk->writeback_chnl) % qblk->activated_channels) + qblk->nr_skip;
	if (unlikely(nr_ch >= qblk->nr_channels))
		nr_ch = nr_ch % qblk->nr_channels;
	return &qblk->ch[nr_ch];
#endif
}


static void qblk_complete_write(struct qblk *qblk,
			struct nvm_rq *rqd,
			struct qblk_c_ctx *c_ctx)
{
	struct qblk_c_ctx *c, *r;
	unsigned long flags;
	unsigned long pos;
	unsigned int rb_count = c_ctx->rb_count;
	struct qblk_rb *rb = qblk_get_rb_by_cpuid(qblk, rb_count);
	struct qblk_queue *queue;
	unsigned int nr_valid;

#ifdef CONFIG_NVM_DEBUG
	atomic_long_sub(c_ctx->nr_valid, &qblk->inflight_writes);
#endif
	//pr_notice("%s, %d\n",
	//		__func__, __LINE__);

	qblk_up_rq(qblk, rqd->ppa_list, rqd->nr_ppas, c_ctx->lun_bitmap);

	qblk_per_rb_account(qblk, c_ctx->rb_count, QBLK_RB_FINISHED, c_ctx->nr_valid);

	pos = qblk_rb_sync_init(rb, &flags);
	BUG_ON(!c_ctx->nr_valid);
	nr_valid = c_ctx->nr_valid;
	if (pos == c_ctx->sentry) {
		//pr_notice("%s,pos==sentry==%lu\n",__func__,pos);
		pos = qblk_end_w_bio(qblk, rqd, c_ctx);

retry:
		//complete queued completions
		list_for_each_entry_safe(c, r, &qblk->complete_list_mq[rb_count], list) {
			BUG_ON(c == c_ctx);
			rqd = nvm_rq_from_c_ctx(c);
			if (c->sentry == pos) {
				//pr_notice("%s,(queued)line=%d,pos==sentry==%lu\n",__func__,__LINE__,pos);
				pos = qblk_end_queued_w_bio(qblk, rqd, c);
				goto retry;
			}
		}
		//("%s,%d\n",__func__,__LINE__);
	} else {
		//Out of order completion! Queue it into the complete_list and complete it in the future
		//pr_notice("%s,pos=%lu,sentry=%u\n",__func__,pos,c_ctx->sentry);
		WARN_ON(nvm_rq_from_c_ctx(c_ctx) != rqd);
		list_add_tail(&c_ctx->list, &qblk->complete_list_mq[rb_count]);
	}
	qblk_rb_sync_end(rb, &flags);
	queue = qblk_queue_by_cpu(qblk, rb_count);
	atomic_sub(nr_valid,
		&queue->inflight_write_secs);
}

static void qblk_end_io_write(struct nvm_rq *rqd)
{
	struct qblk *qblk = rqd->private;
	struct qblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);

	if (rqd->error) {
		qblk_log_write_err(qblk, rqd);
		return;
		//return pblk_end_w_fail(qblk, rqd);//-------
	}
#ifdef CONFIG_NVM_DEBUG
	else
		WARN_ONCE(rqd->bio->bi_status, "qblk: corrupted write error\n");
#endif

#if DEBUGCHNLS
	qblk_debug_complete_time(qblk, c_ctx->logindex, c_ctx->ch_index);
#endif
	qblk_complete_write(qblk, rqd, c_ctx);
	//qblk_debug_complete_time3(qblk, c_ctx->logindex, c_ctx->ch_index);
	qblk_printTimeMonotonic(__func__, __LINE__);

	atomic_dec(&qblk->inflight_io);
	//pr_notice("%s:complete writeToDisk request\n", __func__);
}

static void qblk_end_io_write_meta(struct nvm_rq *rqd)
{
	struct qblk *qblk = rqd->private;
	struct qblk_g_ctx *m_ctx = nvm_rq_to_pdu(rqd);
	struct qblk_line *line = m_ctx->private;
	struct qblk_emeta *emeta = line->emeta;
	int sync;

	if (rqd->error) {
		qblk_log_write_err(qblk, rqd);
		pr_err("qblk: metadata I/O failed. Line %d\n", line->id);
	}

	sync = atomic_add_return(rqd->nr_ppas, &emeta->sync);
	//pr_notice("%s,ch=%d,line=%u,sync=%d\n",
	//		__func__, line->chi->ch_index, line->id, sync);
	if (sync == emeta->nr_entries) {
		qblk_gen_run_ws(qblk, line, NULL, qblk_line_close_ws,
						GFP_ATOMIC, qblk->close_wq);
	}

	qblk_percpu_dma_free(qblk, m_ctx->cpuid, rqd->meta_list, rqd->dma_meta_list);
	qblk_free_rqd(qblk, rqd, QBLK_WRITE_INT);

	//qblk_debug_complete_time(qblk, m_ctx->logindex, line->chi->ch_index);

	atomic_dec(&qblk->inflight_io);
}

void qblk_alloc_w_rq(struct qblk *qblk,
				struct nvm_rq *rqd,
			   unsigned int nr_secs,
			   nvm_end_io_fn(*end_io))
{
	/* Setup write request */
	rqd->opcode = NVM_OP_PWRITE;
	rqd->nr_ppas = nr_secs;
	rqd->flags = qblk_set_progr_mode(qblk, QBLK_WRITE);
	rqd->private = qblk;
	rqd->end_io = end_io;
	rqd->ppa_list = rqd->meta_list + qblk_dma_meta_size;
	rqd->dma_ppa_list = rqd->dma_meta_list + qblk_dma_meta_size;
}

static int qblk_setup_w_rq(struct qblk *qblk,
			struct nvm_rq *rqd,
			unsigned int qcount,
			struct ppa_addr *erase_ppa,
			struct ch_info **pchi)
{
	struct ch_info *chi;
	struct qblk_line *e_line;
	struct qblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	struct qblk_metainfo *metainfo = &qblk->metainfo;
	unsigned int valid = c_ctx->nr_valid;
	unsigned int padded = c_ctx->nr_padded;
	unsigned int nr_secs = valid + padded;
	unsigned long *lun_bitmap;
	int ret;
	int retryCount = 0;
	unsigned int cpuid = smp_processor_id();

retryChi:
	chi =
		qblk_writeback_channel(qblk, qblk_queue_by_cpu(qblk, qcount));

	if(qblk_channel_maynot_writeback(qblk, chi, nr_secs)) {
		retryCount++;
		if (retryCount > QBLK_DRAIN_RETRY_THRESHOLD) {
			//pr_notice("%s, writer %d retry count too high, require[%u]\n",
			//		__func__, qcount, nr_secs);
			retryCount = 0;
			schedule();
		}
		goto retryChi;
	}

	/*
	 * Now we've already acquired enough space budget in this channel.
	 * So, there is no need to change channel from now on.
	 */

	e_line = qblk_line_get_erase(chi);

	//pr_notice("%s, ch = %d\n",
	//		__func__, chi->ch_index);
	lun_bitmap = kzalloc(metainfo->lun_bitmap_len, GFP_KERNEL);
	if (!lun_bitmap)
		return -ENOMEM;
	c_ctx->lun_bitmap = lun_bitmap;
	c_ctx->rb_count = qcount;
#if DEBUGCHNLS
	c_ctx->ch_index = chi->ch_index;
#endif
	c_ctx->cpuid = cpuid;
	rqd->meta_list = qblk_percpu_dma_alloc(qblk, cpuid,
							GFP_KERNEL, &rqd->dma_meta_list);
	if (!rqd->meta_list) {
		kfree(lun_bitmap);
		return ret;
	}
	qblk_alloc_w_rq(qblk, rqd, nr_secs, qblk_end_io_write);

	if (likely(!e_line || !atomic_read(&e_line->left_eblks)))
		qblk_map_rq(qblk, chi, rqd, c_ctx->sentry,
						lun_bitmap, valid, 0, qcount);
	else
		qblk_map_erase_rq(qblk, chi, rqd, c_ctx->sentry,
					lun_bitmap,	valid, erase_ppa, qcount);
	*pchi = chi;
	return 0;
}

static inline bool qblk_valid_meta_ppa(struct qblk *qblk,
				       struct qblk_line *meta_line,
				       struct nvm_rq *data_rqd)
{
	struct qblk_metainfo *meta = &qblk->metainfo;
	u64 offset_inchannel, opt_lun;
	struct qblk_c_ctx *data_c_ctx = nvm_rq_to_pdu(data_rqd);

	/* Schedule a metadata I/O that is half the distance from the data I/O
	 * with regards to the number of LUNs forming the pblk instance. This
	 * balances LUN conflicts across every I/O.
	 *
	 * When the LUN configuration changes (e.g., due to GC), this distance
	 * can align, which would result on metadata and data I/Os colliding. In
	 * this case, modify the distance to not be optimal, but move the
	 * optimal in the right direction.
	 */
	offset_inchannel = qblk_lookup_page(qblk, meta_line);
	opt_lun = ((offset_inchannel + meta->meta_distance) &
		qblk->ppaf.lun_mask_inchnl) >> qblk->ppaf.lun_offset_inchnl;

	//pr_notice("%s, opt_lun=%llu lun_bitmap=0x%lx\n",
	//			__func__, opt_lun, *data_c_ctx->lun_bitmap);

	if (test_bit(opt_lun, data_c_ctx->lun_bitmap))
		return true;

	return false;
}

static struct qblk_line *qblk_should_submit_meta_io(struct qblk *qblk,
					struct nvm_rq *data_rqd, struct ch_info *chi)
{
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct qblk_line *meta_line;

	spin_lock(&chi->close_lock);
retry:
	if (list_empty(&chi->emeta_list)) {
		spin_unlock(&chi->close_lock);
		return NULL;
	}

	meta_line = list_first_entry(&chi->emeta_list, struct qblk_line, list);
	if (meta_line->emeta->mem >= meta->emeta_len[0])
		goto retry;

	list_del(&meta_line->list);
	spin_unlock(&chi->close_lock);

	if (!qblk_valid_meta_ppa(qblk, meta_line, data_rqd)) {
		spin_lock(&chi->close_lock);
		list_add_tail(&meta_line->list, &chi->emeta_list);
		spin_unlock(&chi->close_lock);
		return NULL;
	}
	//pr_notice("%s,metaline=%u\n",__func__,meta_line->id);
	return meta_line;
}

int qblk_submit_meta_io(struct qblk *qblk,
			struct qblk_line *meta_line, struct ch_info *chi)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct qblk_emeta *emeta = meta_line->emeta;
	struct qblk_g_ctx *m_ctx;
	struct bio *bio;
	struct nvm_rq *rqd;
	void *data;
	struct ppa_addr newpage;
	int rq_ppas = qblk->min_write_pgs;
	int rq_len;
	int i, j;
	int ret;
	unsigned long flags;
	unsigned int cpuid = smp_processor_id();

	//pr_notice("%s,ch[%d],line[%u]\n",
	//			__func__, chi->ch_index, meta_line->id);

	rqd = qblk_alloc_rqd_nowait(qblk, QBLK_WRITE_INT);
	if (!rqd)
		return -ENOMEM;

	m_ctx = nvm_rq_to_pdu(rqd);
	m_ctx->private = meta_line;

	rq_len = rq_ppas * geo->sec_size;
	data = ((void *)emeta->buf) + emeta->mem;

	//printBufSample(data);

	bio = qblk_bio_map_addr(qblk, data, rq_ppas, rq_len,
					meta->emeta_alloc_type, GFP_KERNEL);
	if (IS_ERR(bio)) {
		ret = PTR_ERR(bio);
		goto fail_free_rqd;
	}
	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
	rqd->bio = bio;

	//rqd->meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
	//						&rqd->dma_meta_list);
	rqd->meta_list = qblk_percpu_dma_alloc(qblk, cpuid,
							GFP_KERNEL, &rqd->dma_meta_list);
	if (!rqd->meta_list)
		goto fail_free_bio;
	m_ctx->cpuid = cpuid;
	qblk_alloc_w_rq(qblk, rqd, rq_ppas, qblk_end_io_write_meta);

	for (i = 0; i < rqd->nr_ppas; ) {
		spin_lock_irqsave(&meta_line->lock, flags);
		newpage =  __qblk_alloc_page(qblk, meta_line, rq_ppas);
		spin_unlock_irqrestore(&meta_line->lock, flags);
		for (j = 0; j < rq_ppas; j++, i++) {
			rqd->ppa_list[i] = newpage;
			newpage = gen_ppa_add_one_inside_chnl(qblk, newpage);
		}
	}

	emeta->mem += rq_len;
	//pr_notice("%s, rq_len=%d,emeta->mem=%d\n",
	//				__func__, rq_len, emeta->mem);
	if (emeta->mem < meta->emeta_len[0]) {
		spin_lock(&chi->close_lock);
		list_add_tail(&meta_line->list, &chi->emeta_list);
		spin_unlock(&chi->close_lock);
	}

	//logentry.type = QBLK_SUBMIT_EMETA;
	//logentry.firstppa = rqd->ppa_list[0];
	//logentry.nr_secs = rqd->nr_ppas;
	//qblk_debug_time_irqsave(qblk, &m_ctx->logindex,chi->ch_index,logentry );

	//printRqdStatus(rqd);
	ret = qblk_submit_io(qblk, rqd);
	if (ret) {
		pr_err("qblk: emeta I/O submission failed: %d\n", ret);
		goto fail_rollback;
	}

	return NVM_IO_OK;

fail_rollback:
	if (emeta->mem >= meta->emeta_len[0]) {
		spin_lock(&chi->close_lock);
		list_add(&meta_line->list, &meta_line->list);
		spin_unlock(&chi->close_lock);
	}
	qblk_dealloc_page(qblk, chi, meta_line, rq_ppas);
	qblk_percpu_dma_free(qblk, cpuid, rqd->meta_list, rqd->dma_meta_list);
fail_free_bio:
	bio_put(bio);
fail_free_rqd:
	qblk_free_rqd(qblk, rqd, QBLK_WRITE_INT);
	return ret;
}

static int qblk_submit_io_set(struct qblk *qblk,
				struct nvm_rq *rqd, unsigned int qcount)
{

	struct ppa_addr erase_ppa;
	struct qblk_line *meta_line;
	int err;
	struct ch_info *chi;
	struct qblk_c_ctx *c_ctx;
#if DEBUGCHNLS
	struct qblk_debug_entry logentry;
#endif

	qblk_ppa_set_empty(&erase_ppa);

	/* Assign lbas to ppas and populate request structure */
	err = qblk_setup_w_rq(qblk, rqd, qcount, &erase_ppa, &chi);
	if (err) {
		pr_err("qblk: could not setup write request: %d\n", err);
		return NVM_IO_ERR;
	}

	meta_line = qblk_should_submit_meta_io(qblk, rqd, chi);
	//pr_notice("%s:qcount=%u,submit draining write\n",
	//			__func__, qcount);

	/* Submit data write for current data line */
	//printRqdStatus(rqd);
	c_ctx = nvm_rq_to_pdu(rqd);

#if DEBUGCHNLS
	logentry.type = QBLK_SUBMIT_IOWRITE;
	logentry.firstppa = rqd->ppa_list[0];
	logentry.nr_secs = rqd->nr_ppas;
	qblk_debug_time_irqsave(qblk, &c_ctx->logindex, chi->ch_index, logentry);
#endif

	qblk_rq_get_semaphores(qblk, chi, c_ctx->lun_bitmap);
	err = qblk_submit_io_for_ioset(qblk, rqd);
	if (err) {
		pr_err("qblk: data I/O submission failed: %d\n", err);
		return NVM_IO_ERR;
	}

	if (!qblk_ppa_empty(erase_ppa)) {
		/* Submit erase for next data line */
		if (qblk_blk_erase_async(qblk, erase_ppa)) {
			struct qblk_line *e_line = qblk_line_get_erase(chi);
			struct nvm_tgt_dev *dev = qblk->dev;
			struct nvm_geo *geo = &dev->geo;
			int bit;

			atomic_inc(&e_line->left_eblks);
			bit = qblk_ppa_to_posinsidechnl(geo, erase_ppa);
			WARN_ON(!test_and_clear_bit(bit, e_line->erase_bitmap));
		}
	}

	if (meta_line) {
		/* Submit metadata write for previous data line */
		err = qblk_submit_meta_io(qblk, meta_line, chi);
		if (err) {
			pr_err("qblk: metadata I/O submission failed: %d", err);
			return NVM_IO_ERR;
		}
	}

	return NVM_IO_OK;
}

static void qblk_free_write_rqd_bios(struct qblk *qblk, struct nvm_rq *rqd)
{
	struct qblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	struct bio *bio = rqd->bio;

	if (c_ctx->nr_padded)
		qblk_bio_free_pages(qblk, bio, c_ctx->nr_valid,
							c_ctx->nr_padded);
}

static QBLKE_SHOULD_INLINE int qblk_do_writeback(struct qblk *qblk,
									unsigned int qid,
									unsigned int secs_avail,
									unsigned int secs_to_sync)
{
	struct bio *bio;
	struct nvm_rq *rqd;
	struct qblk_queue *pq;
	unsigned int secs_to_com;
	unsigned long pos;
	int ret;
	struct qblk_rb *rb = qblk_get_rb_by_cpuid(qblk, qid);

	rqd = qblk_alloc_rqd_nowait(qblk, QBLK_WRITE);
	if (!rqd) {
		pr_notice("%s: not enough space for rqd\n", __func__);
		return 1;
	}

	bio = bio_alloc(GFP_KERNEL, secs_to_sync);
	if (!bio)
		goto fail_free_rqd;

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

	rqd->bio = bio;
	//pr_notice("secs_to_sync=%u, secs_avail=%u\n", secs_to_sync, secs_avail);
	secs_to_com = (secs_to_sync > secs_avail) ? secs_avail : secs_to_sync;
	pos = qblk_rb_read_commit(qblk, rb, secs_to_com);
	qblk_per_rb_account(qblk, qid, QBLK_RB_COMMITTED, secs_to_com);

	pq = qblk_queue_by_cpu(qblk, qid);
	atomic_add(secs_to_com, &pq->inflight_write_secs);

	ret = qblk_rb_read_to_bio(qblk, rb,
				rqd, pos, secs_to_sync, secs_avail);
	if (ret) {
		pr_err("qblk: corrupted write bio\n");
		goto fail_put_bio;
	}

	//pr_notice("%s: writer[%u] starts to kick, pos=%lu, secsToSync=%u,secsAvai=%u\n",
	//		__func__, qid, pos, secs_to_sync, secs_avail);

	qblk_printTimeMonotonic(__func__, secs_to_com);
	qblk_printTimeMonotonic(__func__, atomic_read(&qblk->inflight_io));

	//pr_notice("%s,mem=%u, subm=%u, sync=%u, l2p=%u, inflight=%u\n",
	//			__func__,
	//			READ_ONCE(rb->mem),
	//			READ_ONCE(rb->subm),
	//			READ_ONCE(rb->sync),
	//			READ_ONCE(rb->l2p_update),
	//			atomic_read(&qblk->inflight_io));
	//qblk_debug_complete_time(qblk,index, qcount);

	if (qblk_submit_io_set(qblk, rqd, qid))
		goto fail_free_bio;
	//qblk_debug_complete_time3(qblk,index, qcount);

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(secs_to_sync, &qblk->sub_writes);
#endif

	return 0;

fail_free_bio:
	qblk_free_write_rqd_bios(qblk, rqd);
fail_put_bio:
	bio_put(bio);
fail_free_rqd:
	if(rqd->meta_list) {
		struct qblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);

		qblk_percpu_dma_free(qblk, c_ctx->cpuid, rqd->meta_list, rqd->dma_meta_list);
	}
	qblk_free_rqd(qblk, rqd, QBLK_WRITE);
	return 1;
}

static int qblk_drain(struct qblk *qblk,
							unsigned int qid,
							unsigned long *psaved_time)
{
	unsigned int flush_point;
	unsigned int has_flushpoint;
	unsigned int secs_avail, secs_to_sync;
	unsigned int secs_to_flush;
	struct qblk_rb *rb = qblk_get_rb_by_cpuid(qblk, qid);
	unsigned long this_time = jiffies;

	/* If there are no sectors in the cache, flushes (bios without data)
	 * will be cleared on the cache threads
	 */
	secs_avail = qblk_rb_read_count(qblk, rb);
	if (!secs_avail)
		return 1;

	has_flushpoint = atomic_read_acquire(&rb->has_flushpoint);
	if (!has_flushpoint) {
		secs_to_flush = 0;
	} else {
		flush_point = smp_load_acquire(&rb->flush_point);
		secs_to_flush = qblk_rb_flush_point_count(qblk, rb, flush_point);
	}

	if (!secs_to_flush && secs_avail < qblk->min_write_pgs) {
		//No flush_point and didn't gather enough pages for wb
		if (*psaved_time &&
				(this_time - *psaved_time) >
					msecs_to_jiffies(2000)) {
			/* If data have been waiting in rb too long,
			 * force to write them back
			 */
			secs_to_flush = secs_avail;
		} else {
			/* We don't have enough pages to wb.
			 * Record the time if not recorded yet.
			 */
			if (!*psaved_time)
				*psaved_time = this_time;
			return 1;
		}
	}

	//pr_notice("%s: secs_avail=%u secs_to_flush=%u\n", __func__, secs_avail, secs_to_flush);
	secs_to_sync = qblk_calc_secs_to_sync(qblk, secs_avail, secs_to_flush);
	//pr_notice("%s: secs_to_sync=%u\n", __func__, secs_to_sync);
	if (secs_to_sync > qblk->max_write_pgs) {
		pr_err("qblk: bad buffer sync calculation\n");
		return 1;
	}

//start to drain data
	//entry.type = QBLK_DRAIN_MARK1;
	//qblk_debug_time_irqsave(qblk,&index, qcount,entry);
	*psaved_time = 0;

	return qblk_do_writeback(qblk, qid, secs_avail, secs_to_sync);
}

int qblk_writer_thread_fn(void *data)
{
	struct qblk_writer_param *param = data;
	struct qblk *qblk = param->qblk;
	unsigned int qid = param->qcount;
	unsigned long saved_time = 0;

	while (!kthread_should_stop()) {
		if (!qblk_drain(qblk, qid, &saved_time))
			continue;
		//pr_notice("%s,goto sleep,qcount=%d\n",__func__, qid);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
		//pr_notice("%s,wake up,qcount=%d\n",__func__, qid);
	}
	return 0;
}

void qblk_write_kick(struct qblk *qblk, unsigned int writer_index)
{
	//pr_notice("%s\n",__func__);
	wake_up_process(qblk->mq_writer_ts[writer_index]);
	mod_timer(&qblk->wtimers[writer_index].timer,
		jiffies + msecs_to_jiffies(QBLK_FUA_MERGE_WINDOW_SIZE));
}


/* kick writer_threads every tick to flush outstanding data */
void qblk_timer_fn(struct timer_list *t)
{
	struct qblk_timer *qt = from_timer(qt, t, timer);
	struct qblk *qblk = qt->qblk;
	int index = qt->index;

	qblk_write_kick(qblk, index);
}

struct qblk_queue *qblk_queue_by_cpu(struct qblk *qblk, unsigned int qcount)
{
	return per_cpu_ptr(qblk->queues, qcount);
}

