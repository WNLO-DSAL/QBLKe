#include "qblk.h"

#define QBLK_MAX_SAVED_ITERS (2)

void __qblk_end_req_io_read(struct qblk *qblk, struct request *req)
{
	blk_mq_end_request(req, BLK_STS_OK);
}

//return 0 if need to retry
static int qblk_read_from_cache(struct qblk *qblk, void *kaddr,
				sector_t lba, struct ppa_addr ppa)
{
	struct qblk_rb *rb = qblk_get_rb_by_cpuid(qblk, ppa.c.q_idx);
	u64 pos = qblk_addr_to_cacheline(ppa);
	struct ppa_addr l2p_ppa;
	struct qblk_rb_entry *entry;
	struct qblk_w_ctx *w_ctx;
	int flags;
	int ret = 1;

#ifdef CONFIG_NVM_DEBUG
	/* Callers must ensure that the ppa points to a cache address */
	BUG_ON(qblk_ppa_empty(ppa));
	BUG_ON(!qblk_addr_in_cache(ppa));
#endif

	entry = qblk_rb_entry_by_index(qblk, rb, pos);
	w_ctx = &entry->w_ctx;
	spin_lock(&rb->w_lock);
	flags = READ_ONCE(w_ctx->flags);
#ifdef QBLK_TRANSMAP_LOCK
	l2p_ppa = qblk_lookup_l2p(qblk, lba);
#else
	l2p_ppa = qblk_trans_map_atomic_get(qblk, lba);
#endif
	if (!qblk_ppa_comp(l2p_ppa, ppa) ||
			w_ctx->lba != lba ||
			flags & QBLK_WRITABLE_ENTRY) {
		ret = 0;
		goto out;
	}
	memcpy(kaddr, entry->data, rb->seg_size);
out:
	spin_unlock(&rb->w_lock);
	return ret;
}

static void qblk_read_put_rqd_kref(struct qblk *qblk, struct nvm_rq *rqd)
{
	struct ppa_addr *ppa_list;
	int i;

	ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;

	for (i = 0; i < rqd->nr_ppas; i++) {
		struct ppa_addr ppa = ppa_list[i];
		struct qblk_line *line = qblk_ppa_to_structline(qblk, ppa);

		kref_put(&line->ref, qblk_line_put_wq);
	}
}

static void qblk_rollback_req(struct bvec_iter *saved_iters, struct request *req)
{
	int p_saved = 0;
	struct req_iterator iter;

	__rq_for_each_bio(iter.bio, req) {
		if (p_saved < QBLK_MAX_SAVED_ITERS) {
			iter.bio->bi_iter = saved_iters[p_saved];
			p_saved++;
		}
	}
}

static void qblk_end_io_read(struct nvm_rq *rqd)
{
	struct qblk *qblk = rqd->private;
	struct qblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct bio *downside_bio = rqd->bio;
	struct request *req = (struct request *)r_ctx->private;
	struct qblk_mq_cmd *qblk_cmd = blk_mq_rq_to_pdu(req);

	if (unlikely(rqd->error)) {
		qblk_log_read_err(qblk, rqd);
		if (rqd->error != NVM_RSP_ERR_EMPTYPAGE)
			qblk_cmd->error = BLK_STS_IOERR;
		else
			qblk_cmd->error = BLK_STS_OK;
	} else {
		qblk_cmd->error = BLK_STS_OK;
	}
	atomic_dec(&qblk->inflight_io);

	blk_mq_complete_request(req);
#if DEBUGCHNLS
	qblk_debug_complete_time(qblk, r_ctx->logindex, r_ctx->ch_index);
#endif

	bio_put(downside_bio);
	qblk_read_put_rqd_kref(qblk, rqd);



#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(rqd->nr_ppas, &qblk->sync_reads);
	atomic_long_sub(rqd->nr_ppas, &qblk->inflight_reads);
#endif

	if(rqd->meta_list)
		qblk_percpu_dma_free(qblk, r_ctx->cpuid, rqd->meta_list, rqd->dma_meta_list);
	qblk_free_rqd(qblk, rqd, QBLK_READ);

}

blk_status_t qblk_read_req_nowait(struct request_queue *q,
					struct qblk *qblk, struct qblk_queue *pq,
					struct request *req)
{
	blk_status_t rv =  BLK_STS_RESOURCE;
	struct nvm_rq *rqd;
	struct req_iterator iter;
	struct bio_vec bvec;
	sector_t blba = qblk_get_rq_lba(req);
	unsigned int nr_secs = qblk_get_rq_secs(req);
	struct ppa_addr ppa;
	int i = 0;
	struct bio *downside_bio;
	void *metalist;
	struct ppa_addr *ppalist;
	dma_addr_t dmaMetaList;
	int nr_toread = 0;
	struct qblk_g_ctx *r_ctx;
	struct bvec_iter saved_iters[QBLK_MAX_SAVED_ITERS];
	int p_saved;
#if DEBUGCHNLS
	struct qblk_debug_entry logentry;
#endif

	if (blba >= qblk->rl.nr_secs || nr_secs > QBLK_MAX_REQ_ADDRS) {
		WARN(1, "qblk: read lba out of bounds (lba:%llu, nr:%d)\n",
					(unsigned long long)blba, nr_secs);
		return BLK_STS_IOERR;
	}

	downside_bio = bio_alloc(GFP_ATOMIC, nr_secs);
	if (!downside_bio) {
		pr_notice("%s, cannot allocate bio, retry later\n", __func__);
		goto errout1;
	}

	//metalist = nvm_dev_dma_alloc(dev->parent, GFP_ATOMIC,
	//						&dmaMetaList);
	metalist = qblk_percpu_dma_alloc(qblk, pq->hctx_idx, GFP_ATOMIC, &dmaMetaList);
	if (!metalist) {
		pr_err("qblk: not able to allocate ppa list\n");
		goto errout2;
	}
	ppalist = (struct ppa_addr *)(metalist + qblk_dma_meta_size);
	//pr_notice("%s, blba=%ld, nr_secs=%u, nrseg=%d\n",
	//	__func__, blba, nr_secs, blk_rq_nr_phys_segments(req));

	p_saved = 0;
	__rq_for_each_bio(iter.bio, req) {
		if (p_saved < QBLK_MAX_SAVED_ITERS) {
			saved_iters[p_saved] = iter.bio->bi_iter;
			p_saved++;
		} else {
			WARN_ON(1);
		}
		bio_for_each_segment(bvec, iter.bio, iter.iter) {
			void *kaddr = page_address(bvec.bv_page);
			unsigned int bvoffset = bvec.bv_offset;
			unsigned int bvlen = bvec.bv_len;

			while (bvlen) {
				WARN_ON(bvlen < QBLK_EXPOSED_PAGE_SIZE);
retry:
#ifdef QBLK_TRANSMAP_LOCK
				ppa = qblk_lookup_l2p(qblk, blba + i);
#else
				ppa = qblk_trans_map_atomic_get(qblk, blba + i);
#endif
				if (qblk_ppa_empty(ppa)) {
					memset(kaddr+bvoffset, 0, QBLK_EXPOSED_PAGE_SIZE);
				} else if (qblk_addr_in_cache(ppa)) {
					//cache hit
					if (!qblk_read_from_cache(qblk,
							kaddr+bvoffset, blba+i, ppa)) {
						goto retry;
					}
				#ifdef CONFIG_NVM_DEBUG
					atomic_long_inc(&qblk->cache_reads);
				#endif
				} else {
					//cache miss
					//get the reference to line
					struct qblk_line *line = qblk_ppa_to_structline(qblk, ppa);
					int ref_nz;

					ref_nz = kref_get_unless_zero(&line->ref);
					if (likely(ref_nz)) {
						unsigned int flipper = READ_ONCE(qblk->write_limiter_flipper);
						struct ch_info *chi = line->chi;

						BUG_ON(flipper > 1);
						if(!READ_ONCE(chi->read_busy[flipper]))
							WRITE_ONCE(chi->read_busy[flipper], 1);
						if (!bio_add_page(downside_bio, bvec.bv_page,
										QBLK_EXPOSED_PAGE_SIZE, bvoffset)) {
												rv = BLK_STS_IOERR;
												pr_notice("%s, cannot add bio page\n", __func__);
												goto errout3;
						}
						ppalist[nr_toread++] = ppa;
					} else {
						/* The line is GCed and the trans_map should be changed.
						 * Just retry.
						 */
						goto retry;
					}
					
				}
				i++;
				bvlen -= QBLK_EXPOSED_PAGE_SIZE;
				bvoffset += QBLK_EXPOSED_PAGE_SIZE;
			}
		}
	}

	if (!nr_toread) {
		//finished
		qblk_percpu_dma_free(qblk, pq->hctx_idx, metalist, dmaMetaList);
		//nvm_dev_dma_free(dev->parent, metalist, dmaMetaList);
		bio_put(downside_bio);
		__qblk_end_req_io_read(qblk, req);
		return BLK_STS_OK;
	}

	//we need to read something from the device
	rqd = qblk_alloc_rqd_nowait(qblk, QBLK_READ);
	if (!rqd) {
		rv = BLK_STS_RESOURCE;
		goto errout4;
	}

	rqd->opcode = NVM_OP_PREAD;
	rqd->bio = downside_bio;
	downside_bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(downside_bio, REQ_OP_READ, 0);
	rqd->nr_ppas = nr_toread;
	rqd->private = qblk;
	rqd->end_io = qblk_end_io_read;
	rqd->error = NVM_IO_OK;
	rqd->meta_list = metalist;
	rqd->dma_meta_list = dmaMetaList;
	if (unlikely(nr_toread == 1)) {
		//only 1 ppa
		rqd->ppa_addr = ppalist[0];
	} else {
		rqd->ppa_list = ppalist;
		rqd->dma_ppa_list = rqd->dma_meta_list + qblk_dma_meta_size;
	}
	if (qblk_io_aligned(qblk, nr_secs))
		rqd->flags = qblk_set_read_mode(qblk, QBLK_READ_SEQUENTIAL);
	else
		rqd->flags = qblk_set_read_mode(qblk, QBLK_READ_RANDOM);
	r_ctx = nvm_rq_to_pdu(rqd);
	r_ctx->private = (void *)req;
	r_ctx->cpuid = pq->hctx_idx;

#if DEBUGCHNLS
	logentry.type = QBLK_SUBMIT_PARTIAL_READ;
	logentry.firstppa = ppalist[0];
	logentry.nr_secs = rqd->nr_ppas;
	r_ctx->ch_index = qblk_ppa_to_chi(qblk, logentry.firstppa)->ch_index;
	qblk_debug_time_irqsave(qblk, &r_ctx->logindex, r_ctx->ch_index, logentry);
#endif

	if (unlikely(qblk_submit_io_for_partialread(qblk, rqd))) {
		rv = BLK_STS_RESOURCE;
		goto errout5;
	}

	return BLK_STS_OK;
errout5:
	mempool_free(rqd, qblk->r_rq_pool);
errout4:
	qblk_rollback_req(saved_iters, req);
	while (nr_toread--) {
		struct qblk_line *line = qblk_ppa_to_structline(qblk, ppalist[nr_toread]);

		kref_put(&line->ref, qblk_line_put);
	}
errout3:
	//nvm_dev_dma_free(dev->parent, metalist, dmaMetaList);
	qblk_percpu_dma_free(qblk, pq->hctx_idx, metalist, dmaMetaList);
errout2:
	bio_put(downside_bio);
errout1:
	return rv;
}

/*
 * From l2p_map users' perspective, the gc procedure should be transparent.
 * We can achieve this goal without locking the whole l2p_map.
 * In other words, we don't need to garantee the atomicity of
 * the whole lookup procedure. We only need to garantee the
 * access atomicity of each l2p entry (By using atomic operations).
 *
 * Here is one example you may concern.
 * 1) The GC routing sellects one victim block.
 *    Physical address of the victim pages are: P1, P2, P3, P4.
 * 2) We get the corresponding logical address: L1, L2, L3, L4.
 * 3) Someone writes to L1. L1 now points to P5.
 * 4) read_ppalist_rq_gc() gets the physical address of these lbas.
 * 5) L2, L3, L4 still points to the victim pages, we migrate these
 *    pages to P6, P7, P8.
 * 6) While migrating, someone writes to L2. L2 now points to P9.
 * 7) Migration finishes, we need to change the l2p_map.
 *    We use atomic_cmpxchg() to set the map entry and get
 *    feedback whether the exchange succeed.
 *    Since the exchange of L2 isn't succeed, we invalidate P6.
 */
static int read_ppalist_rq_gc(struct qblk *qblk, struct nvm_rq *rqd,
			      struct qblk_line *line, u64 *lba_list,
			      u64 *paddr_list_gc, unsigned int nr_secs)
{
	struct ppa_addr ppa_list_l2p[QBLK_MAX_REQ_ADDRS];
	struct ppa_addr ppa_gc;
	struct ch_info *chi = line->chi;
	int valid_secs = 0;
	int i;
	u64 lba;

	for (i = 0; i < nr_secs; i++) {
		lba = lba_list[i];

		if (lba == ADDR_EMPTY)
			continue;
#ifdef QBLK_TRANSMAP_LOCK
		ppa_list_l2p[i] = qblk_lookup_l2p(qblk, lba);
#else
		ppa_list_l2p[i] = qblk_trans_map_atomic_get(qblk, lba);
#endif
		ppa_gc = offset_in_line_to_gen_ppa(qblk, paddr_list_gc[i], chi->ch_index, line->id);
		if (!qblk_ppa_comp(ppa_list_l2p[i], ppa_gc)) {
			paddr_list_gc[i] = lba_list[i] = ADDR_EMPTY;
			continue;
		}

		rqd->ppa_list[valid_secs++] = ppa_list_l2p[i];
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(valid_secs, &qblk->inflight_reads);
#endif

	return valid_secs;
}

/* See comments of read_ppalist_rq_gc() */
static int read_rq_gc(struct qblk *qblk, struct nvm_rq *rqd,
		      struct qblk_line *line, sector_t lba,
		      u64 paddr_gc)
{
	struct ppa_addr ppa_l2p, ppa_gc;
	int valid_secs = 0;
	struct ch_info *chi = line->chi;

	if (lba == ADDR_EMPTY)
		goto out;

	/* logic error: lba out-of-bounds */
	if (lba >= qblk->rl.nr_secs) {
		WARN(1, "qblk: read lba out of bounds\n");
		goto out;
	}

#ifdef QBLK_TRANSMAP_LOCK
	ppa_l2p = qblk_lookup_l2p(qblk, lba);
#else
	ppa_l2p = qblk_trans_map_atomic_get(qblk, lba);
#endif
	ppa_gc = offset_in_line_to_gen_ppa(qblk, paddr_gc, chi->ch_index, line->id);
	if (!qblk_ppa_comp(ppa_l2p, ppa_gc))
		goto out;

	rqd->ppa_addr = ppa_l2p;
	valid_secs = 1;

#ifdef CONFIG_NVM_DEBUG
	atomic_long_inc(&qblk->inflight_reads);
#endif

out:
	return valid_secs;
}


/* This function will wait for read finish. */
int qblk_submit_read_gc(struct qblk_gc *gc, struct qblk_gc_rq *gc_rq)
{
	struct qblk *qblk = gc->qblk;
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct bio *bio;
	struct nvm_rq rqd;
	int data_len;
	int ret = NVM_IO_OK;
	unsigned int cpuid = smp_processor_id();

	memset(&rqd, 0, sizeof(struct nvm_rq));
		
	//rqd.meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
	//						&rqd.dma_meta_list);
	rqd.meta_list = qblk_percpu_dma_alloc(qblk, cpuid,
							GFP_KERNEL, &rqd.dma_meta_list);
	if (!rqd.meta_list)
		return -ENOMEM;

	if (gc_rq->nr_secs > 1) {
		rqd.ppa_list = rqd.meta_list + qblk_dma_meta_size;
		rqd.dma_ppa_list = rqd.dma_meta_list + qblk_dma_meta_size;
					
		gc_rq->secs_to_gc = read_ppalist_rq_gc(qblk, &rqd, gc_rq->line,
							gc_rq->lba_list,
							gc_rq->paddr_list,
							gc_rq->nr_secs);
		if (gc_rq->secs_to_gc == 1)
				rqd.ppa_addr = rqd.ppa_list[0];
	} else {
		gc_rq->secs_to_gc = read_rq_gc(qblk, &rqd, gc_rq->line,
							gc_rq->lba_list[0],
							gc_rq->paddr_list[0]);
	}
	
	if (!(gc_rq->secs_to_gc))
		goto out;
			
	data_len = (gc_rq->secs_to_gc) * geo->sec_size;
	bio = qblk_bio_map_addr(qblk, gc_rq->data, gc_rq->secs_to_gc, data_len,
						QBLK_VMALLOC_META, GFP_KERNEL);
	if (IS_ERR(bio)) {
		pr_err("qblk: could not allocate GC bio (%lu)\n", PTR_ERR(bio));
		goto err_free_dma;
	}
					
	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
				
	rqd.opcode = NVM_OP_PREAD;
	rqd.nr_ppas = gc_rq->secs_to_gc;
	rqd.flags = qblk_set_read_mode(qblk, QBLK_READ_RANDOM);
	rqd.bio = bio;

	//printRqdStatus(&rqd);
#ifdef QBLKe_DEBUG
	atomic_add(gc_rq->secs_to_gc, &qblk->rl.gc_read);
#endif
				
	if (qblk_submit_io_sync(qblk, &rqd)) {
		ret = -EIO;
		pr_err("qblk: GC read request failed\n");
		goto err_free_bio;
	}
			
	atomic_dec(&qblk->inflight_io);
					
	if (rqd.error) {
		atomic_long_inc(&qblk->read_failed_gc);
#ifdef CONFIG_NVM_DEBUG
		qblk_print_failed_rqd(qblk, &rqd, rqd.error);
#endif
	}
			
#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(gc_rq->secs_to_gc, &qblk->sync_reads);
	atomic_long_add(gc_rq->secs_to_gc, &qblk->recov_gc_reads);
	atomic_long_sub(gc_rq->secs_to_gc, &qblk->inflight_reads);
#endif
					
out:
	//nvm_dev_dma_free(dev->parent, rqd.meta_list, rqd.dma_meta_list);
	qblk_percpu_dma_free(qblk, cpuid, rqd.meta_list, rqd.dma_meta_list);
	return ret;
	
err_free_bio:
	bio_put(bio);
err_free_dma:
	//nvm_dev_dma_free(dev->parent, rqd.meta_list, rqd.dma_meta_list);
	qblk_percpu_dma_free(qblk, cpuid, rqd.meta_list, rqd.dma_meta_list);
	return ret;
}

