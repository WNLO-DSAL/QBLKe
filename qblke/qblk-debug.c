#include "qblk.h"

#define TEST_SECS_PER_REQ (8)
#define TEST_SECS_ORDER_PER_REQ (3)

struct qblk_debug_tracker {
	struct delayed_work dw;
	struct qblk *qblk;
	unsigned long print_count;
	unsigned long usr_accepted;
	unsigned long usr_submitted;
	unsigned long gc_accepted;
	unsigned long gc_submitted;
	unsigned long usr_queued;
	unsigned long gc_queued;
	unsigned long gc_read;
	unsigned long gc_prewrite;
	unsigned long gc_read_rq;
	unsigned long gc_write_rq;
	unsigned long gc_create_rq;
	unsigned long gc_read_queued;
};

struct qblk_status_header {
	unsigned long nr_rb;
	unsigned long nr_chnl;
};

struct qblk_status_rb {
	unsigned long mem;
	unsigned long subm;
	unsigned long sync;
	unsigned long flush_point;
	unsigned long l2p_update;
	unsigned long entries[QBLK_RB_ACCOUNTING_ENTRIES];
};

struct qblk_status_chnl {
	unsigned long current_data_line;
	unsigned long current_data_next;
	unsigned long free_blocks;
	unsigned long free_user_blocks;
	unsigned long pch_rb_user_max;
	unsigned long chnl_state;
	unsigned long remain_secs;
};

struct fake_io_work {
	struct work_struct work;
	struct qblk *qblk;
	struct nvm_rq *rqd;
};

static struct qblk *debugqblk;
spinlock_t debug_printlock;

static char ls_name[30][30] = {"TYPE_FREE",
								"TYPE_LOG",
								"TYPE_DATA",
								"",
								"",
								"",
								"",
								"",
								"",
								"NEW",
								"FREE",
								"OPEN",
								"CLOSED",
								"GC",
								"BAD",
								"CORRUPT",
								"",
								"",
								"",
								"",
								"GC_NONE",
								"GC_EMPTY",
								"GC_LOW",
								"GC_MID",
								"GC_HIGH",
								"GC_FULL"
								};

void qblk_printBioStatus (struct bio *bio){
	int i;
	unsigned long *p;
	if(!bio){
		pr_notice("===printBioStatus===bio==NULL\n");
		return;
	}
	pr_notice("----------printBioStatus----------------\n");
	pr_notice("bi_opf=0x%x,__bi_cnt=%d,status=0x%x,vcnt=%d\n",bio->bi_opf,atomic_read(&bio->__bi_cnt),bio->bi_status,(int)bio->bi_vcnt);
							
	pr_notice("iter.sector=%lu,size=%u,idx=%u,done=%u,vecdone=%u\n",
		bio->bi_iter.bi_sector,bio->bi_iter.bi_size,bio->bi_iter.bi_idx,
		bio->bi_iter.bi_done,bio->bi_iter.bi_bvec_done);
								
	for(i=0;i<bio->bi_vcnt;i++){
		p = (unsigned long *)page_address(bio->bi_io_vec[i].bv_page);
		pr_notice("page=%p,p=0x%lx,len=0x%x,offset=0x%x\n",
										page_address(bio->bi_io_vec[i].bv_page),
										(unsigned long)p,
										bio->bi_io_vec[i].bv_len,
										bio->bi_io_vec[i].bv_offset);
									//pr_notice("data=%lx %lx %lx %lx\n",p[0],p[1],p[2],p[3]);
	}
								
	pr_notice("----------EndOf{PrintBioStatus}----------------\n");
							
}

void printRqdStatus(struct nvm_rq *rqd)
{
	int i;
	struct ppa_addr *p_ppa;
	struct qblk_c_ctx *c_ctx;

	c_ctx = nvm_rq_to_pdu(rqd);

	pr_notice("---------%s-------\n", __func__);

	pr_notice("c_ctx{sentry[%u]nr_valid[%u]npad[%u]rb[%u]}\n",
				c_ctx->sentry, c_ctx->nr_valid,
				c_ctx->nr_padded,
				c_ctx->rb_count);

	pr_notice("opcode[0x%x] nr_ppas[%u] \n",
				rqd->opcode, rqd->nr_ppas);
	if (rqd->nr_ppas == 1) {
		pr_notice("ppa[0x%llx]\n", rqd->ppa_addr.ppa);
	}
	else {
		p_ppa = rqd->ppa_list;
		for (i = 0; i < rqd->nr_ppas; i++) {
			pr_notice("ppa[%llx]\n", p_ppa->ppa);
			p_ppa++;
		}
	}

	qblk_printBioStatus(rqd->bio);
	pr_notice("<<<<<<%s>>>>>>\n", __func__);
}

int qblk_check_io(struct qblk *qblk, struct nvm_rq *rqd)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct ppa_addr *ppa_list;

	if (!rqd->nr_ppas) {
		spin_lock(&debug_printlock);
		WARN(1, "QBLK: wrong nr_ppas\n");
		printRqdStatus(rqd);
		spin_unlock(&debug_printlock);
		return -EINVAL;
	}
	ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;

	if (qblk_boundary_ppa_checks(dev, ppa_list, rqd->nr_ppas)) {
		spin_lock(&debug_printlock);
		WARN(1, "QBLK: boundary_ppa_check_failed\n");
		printRqdStatus(rqd);
		spin_unlock(&debug_printlock);
		return -EINVAL;
	}

	if (rqd->opcode == NVM_OP_PWRITE) {
		struct qblk_line *line;
		struct ppa_addr ppa;
		int i;

		for (i = 0; i < rqd->nr_ppas; i++) {
			struct ch_info *chi;

			ppa = ppa_list[i];
			chi = qblk_ppa_to_chi(qblk, ppa);
			line = &chi->lines[qblk_ppa_to_line(ppa)];

			spin_lock(&line->lock);
			if (line->state != QBLK_LINESTATE_OPEN) {
				pr_err("qblk: write to non-open line: chnl %d, line:%d, state:%d\n",
							chi->ch_index, line->id, line->state);
				spin_unlock(&line->lock);
				spin_lock(&debug_printlock);
				WARN(1, "QBLK: wrong line state %d\n", line->state);
				printRqdStatus(rqd);
				spin_unlock(&debug_printlock);
				return -EINVAL;
			}
			spin_unlock(&line->lock);
		}
	}

	return 0;
}

void qblk_debug_check_line_put(struct qblk_line *line)
{
	if(line->state != QBLK_LINESTATE_GC) {
		spin_lock(&debug_printlock);
		pr_notice("%s, put non-GC line. ch[%d] line[%d] state[%d].\n",
					__func__, line->chi->ch_index, line->id, line->state);
		dump_stack();
		spin_unlock(&debug_printlock);
	}
}

static void fake_submit_callback(struct work_struct *work)
{
	struct fake_io_work *fake_work = container_of(work, struct fake_io_work, work);
	struct nvm_rq *rqd = fake_work->rqd;

	kfree(fake_work);
	rqd->error = 0;
	if (rqd->end_io)
		rqd->end_io(rqd);
}

int qblkdebug_fake_submit_io_nowait(struct qblk *qblk, struct nvm_rq *rqd)
{
	struct fake_io_work *fake_work = kmalloc(sizeof(*fake_work), GFP_ATOMIC);

	if (!fake_work)
		return -ENOMEM;

	fake_work->qblk = qblk;
	fake_work->rqd = rqd;

	INIT_WORK(&fake_work->work, fake_submit_callback);
	schedule_work(&fake_work->work);
	return 0;
}


int qblkdebug_fake_submit_io_sync(struct qblk *qblk, struct nvm_rq *rqd)
{
	rqd->error = 0;
	if (rqd->end_io)
		rqd->end_io(rqd);
	return 0;
}

void printBufSample(void *data)
{
	int i;
	unsigned long long *p = data;

	pr_notice("---------%s-------\n", __func__);
	for (i = 0; i < 16; i++) {
		pr_notice("0x%llx\n", *p);
		p++;
	}
	pr_notice("<<<<<<%s>>>>>>\n", __func__);
}

void print_gcrq_status(struct qblk_gc_rq *gc_rq)
{
	int nsec = gc_rq->nr_secs;
	int i;

	pr_notice("---------%s-------\n", __func__);
	pr_notice("ch[%d], line[%u], nrsecs[%d], secstogc[%d]\n",
				gc_rq->chi->ch_index, gc_rq->line->id,
				gc_rq->nr_secs,
				gc_rq->secs_to_gc);
	for (i = 0; i < nsec; i++) {
		pr_notice("lba[0x%llx], ppa[0x%llx]\n",
						gc_rq->lba_list[i],
						gc_rq->paddr_list[i]);
	}
	
	pr_notice("<<<<<<%s>>>>>>\n", __func__);
}

/*-------------------------------printDebug------------------------------*/

static void qblk_print_debugentry(struct qblk_debug_entry *entry, int index)
{
	struct timeval *time1 = &entry->time;
	struct timeval *time2 = &entry->time2;
	struct timeval *time3 = &entry->time3;

	pr_notice("type=%d=TS=%ld=ppa=%x=%x=%x=%x=%x=%x=NS=%d=ts1=%ld=tus1=%ld=ts2=%ld=tus2=%ld=ts3=%ld=tus3=%ld\n",
		entry->type,
		1000000 * (time2->tv_sec-time1->tv_sec) +
			time2->tv_usec - time1->tv_usec,
		entry->firstppa.g.ch, entry->firstppa.g.lun,
		entry->firstppa.g.pl, entry->firstppa.g.sec,
		entry->firstppa.g.pg, entry->firstppa.g.blk,
		entry->nr_secs,
		time1->tv_sec, time1->tv_usec,
		time2->tv_sec, time2->tv_usec,
		time3->tv_sec, time3->tv_usec
		);
}

static void qblk_print_debug(struct qblk *qblk,
			int chnl, int irqsave)
{
	struct qblk_debug_header *header =
					&qblk->debugHeaders[chnl];
	unsigned long flags;
	int i;
	int end;

	if (chnl >= DEBUGCHNLS)
		return;

	if (irqsave)
		spin_lock_irqsave(&qblk->debug_printing_lock, flags);
	else
		spin_lock(&qblk->debug_printing_lock);
	spin_lock(&header->lock);
	end = header->p;
	pr_notice("------------print logs of ch[%d]---------------\n", chnl);
	for (i = 0; i < end; i++)
		qblk_print_debugentry(&header->entries[i], i);
	pr_notice("============print logs of ch[%d]===============\n", chnl);
	header->p = 0;
	spin_unlock(&header->lock);
	if (irqsave)
		spin_unlock_irqrestore(&qblk->debug_printing_lock, flags);
	else
		spin_unlock(&qblk->debug_printing_lock);
}

void qblk_debug_complete_time(struct qblk *qblk,
			int index, int chnl)
{
	struct qblk_debug_header *header =
					&qblk->debugHeaders[chnl];

	if (!qblk->debugstart)
		return;
	if (chnl >= DEBUGCHNLS)
		return;
	if (index < 0)
		return;
	do_gettimeofday(&header->entries[index].time2);
}

void qblk_debug_complete_time3(struct qblk *qblk,
			int index, int chnl)
{
	struct qblk_debug_header *header =
					&qblk->debugHeaders[chnl];

	if (!qblk->debugstart)
		return;
	if (chnl >= DEBUGCHNLS)
		return;
	if (index < 0)
		return;
	do_gettimeofday(&header->entries[index].time3);
}

void qblk_debug_time_irqsave(struct qblk *qblk,
			int *pindex, int chnl,
			struct qblk_debug_entry entry)
{
	struct qblk_debug_header *header =
					&qblk->debugHeaders[chnl];
	unsigned long flags;
	int index;
	struct qblk_debug_entry *debug_entry;

	if (!qblk->debugstart)
		return;
	if (chnl >= DEBUGCHNLS)
		return;
	spin_lock_irqsave(&header->lock, flags);
	index = header->p++;
	if (index >= QBLK_DEBUG_ENTRIES_PER_CHNL) {
		header->p--;
		spin_unlock_irqrestore(&header->lock, flags);
		if (pindex)
			*pindex = -1;
		return;
	}
	spin_unlock_irqrestore(&header->lock, flags);

	debug_entry = &header->entries[index];
	debug_entry->type = entry.type;
	debug_entry->firstppa = entry.firstppa;
	debug_entry->nr_secs = entry.nr_secs;
	do_gettimeofday(&debug_entry->time);
	if (pindex)
		*pindex = index;
}

void qblk_debug_time(struct qblk *qblk,
				int *pindex, int chnl,
				struct qblk_debug_entry entry)
{
	struct qblk_debug_header *header =
				&qblk->debugHeaders[chnl];
	int index;
	struct qblk_debug_entry *debug_entry;

	if (chnl >= DEBUGCHNLS)
		return;
	if (!qblk->debugstart)
		return;
	spin_lock(&header->lock);
	index = header->p++;
	if (index >= QBLK_DEBUG_ENTRIES_PER_CHNL) {
		header->p--;
		spin_unlock(&header->lock);
		if (pindex)
			*pindex = -1;
		return;
	}
	spin_unlock(&header->lock);

	debug_entry = &header->entries[index];
	debug_entry->type = entry.type;
	debug_entry->firstppa = entry.firstppa;
	debug_entry->nr_secs = entry.nr_secs;
	do_gettimeofday(&header->entries[index].time);
	if (pindex)
		*pindex = index;
}


/*-------------------------------IOtest------------------------------*/

static void qblk_end_test_ioerase(struct nvm_rq *rqd)
{
	struct qblk *qblk = rqd->private;

	mempool_free(rqd, qblk->e_rq_pool);
	atomic_dec(&qblk->inflight_io);
}


int qblk_blk_erase_test_async(struct qblk *qblk, struct ppa_addr ppa)
{
	struct nvm_rq *rqd;
	int err;

	rqd = qblk_alloc_rqd_nowait(qblk, QBLK_ERASE);
	if (!rqd)
		return -ENOMEM;

	rqd->opcode = NVM_OP_ERASE;
	rqd->ppa_addr = ppa;
	rqd->nr_ppas = 1;
	rqd->flags = qblk_set_progr_mode(qblk, QBLK_ERASE);
	rqd->bio = NULL;

	rqd->end_io = qblk_end_test_ioerase;
	rqd->private = qblk;

	/* The write thread schedules erases so that it minimizes disturbances
	 * with writes. Thus, there is no need to take the LUN semaphore.
	 */
	err = qblk_submit_io(qblk, rqd);
	if (err)
		pr_err("qblk: could not async erase line:%d,ppa:0x%llx\n",
					qblk_ppa_to_line(ppa),
					ppa.ppa);

	return err;
}


static void qblk_end_test_async_iowrite(struct nvm_rq *rqd)
{
	struct qblk *qblk = rqd->private;
	struct qblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);

	if (rqd->error) {
		pr_err("%s, err=%d\n", __func__, rqd->error);
		return;
	}
#if DEBUGCHNLS
	if (c_ctx->nr_padded)
		qblk_debug_complete_time(qblk, c_ctx->logindex, c_ctx->ch_index);
#endif
	atomic_dec(&qblk->inflight_io);
	free_pages((unsigned long)c_ctx->lun_bitmap, TEST_SECS_ORDER_PER_REQ);
	bio_put(rqd->bio);
	qblk_percpu_dma_free(qblk, c_ctx->cpuid, rqd->meta_list, rqd->dma_meta_list);
	qblk_free_rqd(qblk, rqd, QBLK_WRITE);
#if DEBUGCHNLS
	if (c_ctx->nr_padded)
		qblk_debug_complete_time3(qblk, c_ctx->logindex, c_ctx->ch_index);
#endif
}

static void qblk_end_test_async_ioread(struct nvm_rq *rqd)
{
	struct qblk *qblk = rqd->private;
	struct qblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);

	if (rqd->error) {
		pr_err("%s, err=0x%x\n", __func__, rqd->error);
	}

	free_pages((unsigned long)r_ctx->private, 6);
	bio_put(rqd->bio);
	qblk_percpu_dma_free(qblk, r_ctx->cpuid, rqd->meta_list, rqd->dma_meta_list);
	qblk_free_rqd(qblk, rqd, QBLK_READ);
	qblk_printTimeMonotonic(__func__, __LINE__);
}


static int __attribute__ ((unused)) qblk_submit_test_ioread_async(struct qblk *qblk,
				struct ppa_addr *ppa_list, int nr_ppa) {
	struct nvm_rq *rqd;
	struct bio *bio;
	int i;
	struct qblk_g_ctx *r_ctx;
	unsigned int cpuid = smp_processor_id();
	struct ppa_addr *rqd_ppa_list;
	int ret;
	unsigned long data;
	struct request_queue *q = qblk->dev->q;

	if (nr_ppa == 1)
		return 0;

	rqd = qblk_alloc_rqd_nowait(qblk, QBLK_READ);
	if (!rqd) {
		pr_notice("%s: not enough space for rqd\n", __func__);
		return 1;
	}

	bio = bio_alloc(GFP_KERNEL, TEST_SECS_PER_REQ);
	if (!bio) {
		pr_err("%s: not enough space for bio\n", __func__);
		return 1;
	}

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_READ, 0);

	rqd->meta_list = qblk_percpu_dma_alloc(qblk, cpuid,
						GFP_ATOMIC, &rqd->dma_meta_list);
	rqd->bio = bio;
	rqd->opcode = NVM_OP_PREAD;
	rqd->nr_ppas = nr_ppa;
	rqd->private = qblk;
	rqd->end_io = qblk_end_test_async_ioread;
	rqd->error = NVM_IO_OK;
	rqd_ppa_list = rqd->ppa_list = rqd->meta_list + qblk_dma_meta_size;
	rqd->dma_ppa_list = rqd->dma_meta_list + qblk_dma_meta_size;
	rqd->flags = qblk_set_read_mode(qblk, QBLK_READ_RANDOM);
	r_ctx = nvm_rq_to_pdu(rqd);
	r_ctx->cpuid = cpuid;

	data = __get_free_pages(GFP_ATOMIC, 6);
	if (!data) {
		pr_err("%s: not enough space for data\n", __func__);
		//FIXME
		return 1;
	}
	for (i = 0; i < nr_ppa; i++) {
		struct page *page = virt_to_page(data+i*PAGE_SIZE);

		bio_add_pc_page(q, bio, page, PAGE_SIZE, 0);
	}
	r_ctx->private = (void *)data;

	for (i = 0; i < nr_ppa; i++) {
		rqd_ppa_list[i] = ppa_list[i];
	}

	qblk_printTimeMonotonic(__func__, __LINE__);
	ret = qblk_submit_io_nowait(qblk, rqd);
	if (ret) {
		pr_notice("%s, submit failed. err=%d.", __func__, ret);
		goto freeout;
	}
	return 0;
freeout:
	qblk_percpu_dma_free(qblk, cpuid, rqd->meta_list, rqd->dma_meta_list);
	bio_put(bio);
	qblk_free_rqd(qblk, rqd, QBLK_READ);
	return ret;
}


static int qblk_submit_test_iowrite_async(struct qblk *qblk,
				struct ppa_addr ppa_addr, int logtime)
{
	struct nvm_rq *rqd;
	struct bio *bio;
	unsigned long data;
	int i;
	struct request_queue *q = qblk->dev->q;
	struct ppa_addr *ppa_list;
#if DEBUGCHNLS
	struct qblk_debug_entry logentry;
#endif
	struct qblk_c_ctx *c_ctx;
	int err;
	unsigned int cpuid = smp_processor_id();

	rqd = qblk_alloc_rqd_nowait(qblk, QBLK_WRITE);
	if (!rqd) {
		pr_notice("%s: not enough space for rqd\n", __func__);
		return 1;
	}

	bio = bio_alloc(GFP_KERNEL, TEST_SECS_PER_REQ);
	if (!bio) {
		pr_err("%s: not enough space for bio\n", __func__);
		return 1;
	}

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

	rqd->meta_list = qblk_percpu_dma_alloc(qblk, cpuid,
						GFP_ATOMIC, &rqd->dma_meta_list);
	rqd->bio = bio;
	qblk_alloc_w_rq(qblk, rqd, TEST_SECS_PER_REQ,
				qblk_end_test_async_iowrite);

	data = __get_free_pages(GFP_ATOMIC, TEST_SECS_ORDER_PER_REQ);
	if (!data) {
		pr_err("%s: not enough space for data\n", __func__);
		return 1;
	}
	for (i = 0; i < TEST_SECS_PER_REQ; i++) {
		struct page *page = virt_to_page(data+i*PAGE_SIZE);

		bio_add_pc_page(q, bio, page, PAGE_SIZE, 0);
	}

	ppa_list = rqd->ppa_list;
	for (i = 0 ; i < TEST_SECS_PER_REQ; i++) {
		ppa_list[i] = ppa_addr;
		ppa_addr = gen_ppa_add_one_inside_chnl(qblk, ppa_addr);
	}

	c_ctx = nvm_rq_to_pdu(rqd);
	c_ctx->cpuid = cpuid;
	c_ctx->lun_bitmap = (unsigned long *)data;
	c_ctx->nr_padded = logtime;
#if DEBUGCHNLS
	c_ctx->ch_index = ppa_addr.g.ch;	
	logentry.type = QBLK_SUBMIT_IOWRITE;
	logentry.firstppa = rqd->ppa_list[0];
	logentry.nr_secs = rqd->nr_ppas;

	if (logtime)
		qblk_debug_time_irqsave(qblk, &c_ctx->logindex,
						ppa_addr.g.ch, logentry);
#endif

	err = qblk_submit_io(qblk, rqd);
	if (err) {
		pr_err("qblk: data I/O submission failed: %d\n", err);
		return NVM_IO_ERR;
	}
	return 0;

}


static int qblk_submit_test_iowrite_sync(struct qblk *qblk,
					struct ppa_addr ppa_addr, int logtime)
{
	struct nvm_rq rqd;
	struct bio *bio;
	unsigned long data;
	int i;
	struct request_queue *q = qblk->dev->q;
	struct ppa_addr *ppa_list;
	struct qblk_debug_entry logentry;
	int logindex;
	int err;
	unsigned int cpuid = smp_processor_id();

	memset(&rqd, 0, sizeof(struct nvm_rq));

	bio = bio_alloc(GFP_KERNEL, TEST_SECS_PER_REQ);
	if (!bio) {
		pr_err("%s: not enough space for bio\n", __func__);
		return 1;
	}

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

	rqd.bio = bio;
	data = __get_free_pages(GFP_ATOMIC, TEST_SECS_ORDER_PER_REQ);
	if (!data) {
		pr_err("%s: not enough space for data\n", __func__);
		return 1;
	}
	for (i = 0; i < TEST_SECS_PER_REQ; i++) {
		struct page *page = virt_to_page(data+i*PAGE_SIZE);

		bio_add_pc_page(q, bio, page, PAGE_SIZE, 0);
	}

	//rqd.meta_list = nvm_dev_dma_alloc(dev->parent, GFP_ATOMIC,
	//						&rqd.dma_meta_list);
	rqd.meta_list = qblk_percpu_dma_alloc(qblk, cpuid,
							GFP_KERNEL, &rqd.dma_meta_list);
	if (!rqd.meta_list)
		return -ENOMEM;

	rqd.ppa_list = rqd.meta_list + qblk_dma_meta_size;
	rqd.dma_ppa_list = rqd.dma_meta_list + qblk_dma_meta_size;

	rqd.opcode = NVM_OP_PWRITE;
	rqd.flags = qblk_set_progr_mode(qblk, QBLK_WRITE);
	rqd.nr_ppas = TEST_SECS_PER_REQ;

	ppa_list = rqd.ppa_list;
	for (i = 0; i < TEST_SECS_PER_REQ; i++) {
		ppa_list[i] = ppa_addr;
		ppa_addr = gen_ppa_add_one_inside_chnl(qblk, ppa_addr);
	}

	logentry.type = QBLK_SUBMIT_IOWRITE;
	logentry.firstppa = rqd.ppa_list[0];
	logentry.nr_secs = rqd.nr_ppas;
	if (logtime)
		qblk_debug_time_irqsave(qblk, &logindex, ppa_addr.g.ch, logentry);
	err = qblk_submit_io_sync(qblk, &rqd);
	if (err) {
		pr_err("qblk: data I/O submission failed: %d\n", err);
		return NVM_IO_ERR;
	}
	if (logtime)
		qblk_debug_complete_time(qblk, logindex, ppa_addr.g.ch);
	atomic_dec(&qblk->inflight_io);

	if (rqd.error)
		pr_err("%s, err = %d\n", __func__, rqd.error);

	//nvm_dev_dma_free(dev->parent, rqd.meta_list, rqd.dma_meta_list);
	qblk_percpu_dma_free(qblk, cpuid, rqd.meta_list, rqd.dma_meta_list);
	free_pages(data, TEST_SECS_ORDER_PER_REQ);
	bio_put(bio);
	return 0;

}

/* usage: "te"*/
static void qblk_iotest(struct qblk *qblk)
{
	struct ppa_addr ppa;
	//int logindex;
	struct qblk_debug_entry entry;
	int ch, lun;
	int pg;
	int blk;
	int pl;

	return;

	pr_notice("--------------------------------test begin\n");
	ppa.g.ch = 0;
	ppa.g.lun = 0;
	ppa.g.pl = 0;
	ppa.g.sec = 0;
	ppa.g.blk = 6;

	entry.nr_secs = 1;
	entry.type = QBLK_SUBMIT_SYNC_ERASE;
	for (blk = 2; blk < 2; blk++) {
		pr_emerg("%s, erasing blk[%d]\n", __func__, blk);
		for (ch = 0; ch < 17; ch++) {
			for (lun = 0; lun < 4; lun++) {
				for (pl = 0; pl < 2; pl++) {
					ppa.g.ch = ch;
					ppa.g.lun = lun;
					ppa.g.blk = blk;
					ppa.g.pl = pl;
					entry.firstppa = ppa;
					//qblk_debug_time_irqsave(qblk, &logindex, ch, entry);
					qblk_blk_erase_test_async(qblk, ppa);
					//qblk_debug_complete_time(qblk, logindex, ch);
				}
			}
		}
	}
	//msleep(1000);

	ppa.g.blk = 6;
	for (pg = 0; pg < 4; pg++) {
		for (lun = 0; lun < 4; lun++) {
			for (ch = 0; ch < 1; ch++) {
				ppa.g.pg = pg;
				ppa.g.ch = ch;
				ppa.g.lun = lun;
				//qblk_submit_test_iowrite_async(qblk, ppa,1);
				qblk_submit_test_iowrite_sync(qblk, ppa, 1);

			}
		}
	}

	//msleep(1000);
	for (pg = 0; pg < 4; pg++) {
		for (lun = 0; lun < 4; lun++) {
			for (ch = 0; ch < 1; ch++) {
				ppa.g.pg = pg;
				ppa.g.ch = ch;
				ppa.g.lun = lun;
				//qblk_submit_test_iowrite_async(qblk, ppa,1);
				qblk_submit_test_iowrite_sync(qblk, ppa, 1);

			}
		}
	}

	for (pg = 0; pg < 4; pg++) {
		for (lun = 0; lun < 4; lun++) {
			for (ch = 0; ch < 1; ch++) {
				ppa.g.pg = pg;
				ppa.g.ch = ch;
				ppa.g.lun = lun;
				//qblk_submit_test_iowrite_async(qblk, ppa,1);
				qblk_submit_test_iowrite_sync(qblk, ppa, 1);
			}
		}
	}

	//msleep(1000);
	qblk_print_debug(qblk, 0, 1);
	return;
//=================================================================
	ppa.g.blk = 6;
	ppa.g.ch = 17;
	ppa.g.lun = 0;

	for (pg = 0; pg < 8; pg++) {
		qblk_submit_test_iowrite_async(qblk, ppa, 0);
		ppa.g.pg++;
	}
//-----------------------------------------------------------------
	ppa.g.ch = ch;
	ppa.g.lun = lun;
	ppa.g.blk = blk;
	entry.firstppa = ppa;
	//qblk_debug_time_irqsave(qblk, &logindex, ch, entry);
	qblk_blk_erase_test_async(qblk, ppa);
	//qblk_debug_complete_time(qblk, logindex, ch);
}
//-------------------------------------------------------------------------------------------------

#if 0
/*-------------------------------debugA------------------------------*/
void debugA1(struct qblk *qblk)
{
	struct ppa_addr ppa;
	int i,j;

	ppa.ppa = 0;
	ppa.g.blk = 16;
	for (i = 0; i < 8; i++) {
		for (j = 0; j < 4; j++) {
			ppa.g.lun = j;
			ppa.g.pg = i;
			//pr_notice("%s, 0x%llx\n", __func__, ppa.ppa);
			qblk_submit_test_iowrite_async(qblk, ppa, 0);
		}
	}
}

void debugA2(struct qblk *qblk)
{
	struct ppa_addr ppalist[8];
	static int run=0;

	run++;

	ppalist[0].ppa = 0x10;
	ppalist[1].ppa = 0x1000000000010;
	qblk_submit_test_ioread_async(qblk, ppalist, 2);
	if (run < 2)
		return;

	ppalist[0].ppa = 0x2000000000010;
	ppalist[1].ppa = 0x3000000000010;
	qblk_submit_test_ioread_async(qblk, ppalist, 2);
	if (run < 3)
		return;
	//---------------------------------------------------

	ppalist[0].ppa = 0x10010;
	ppalist[1].ppa = 0x1000000010010;
	ppalist[2].ppa = 0x2000000010010;
	ppalist[3].ppa = 0x3000000010010;
	qblk_submit_test_ioread_async(qblk, ppalist, 4);
	if (run < 4)
		return;
	ppalist[0].ppa = 0x100010010;
	ppalist[1].ppa = 0x1000100010010;
	ppalist[2].ppa = 0x2000100010010;
	ppalist[3].ppa = 0x3000100010010;
	qblk_submit_test_ioread_async(qblk, ppalist, 4);
	if (run < 5)
		return;
	ppalist[0].ppa = 0x200010010;
	ppalist[1].ppa = 0x1000200010010;
	ppalist[2].ppa = 0x2000200010010;
	ppalist[3].ppa = 0x3000200010010;
	qblk_submit_test_ioread_async(qblk, ppalist, 4);
	if (run < 6)
		return;
	ppalist[0].ppa = 0x300010010;
	ppalist[1].ppa = 0x1000300010010;
	ppalist[2].ppa = 0x2000300010010;
	ppalist[3].ppa = 0x3000300010010;
	qblk_submit_test_ioread_async(qblk, ppalist, 4);
	if (run < 7)
		return;
	//---------------------------------------------------

	ppalist[0].ppa = 0x20010;
	ppalist[1].ppa = 0x200020010;
	ppalist[2].ppa = 0x1000000020010;
	ppalist[3].ppa = 0x1000100020010;
	qblk_submit_test_ioread_async(qblk, ppalist, 4);
	if (run < 8)
		return;
	ppalist[0].ppa = 0x10000020010;
	ppalist[1].ppa = 0x10100020010;
	ppalist[2].ppa = 0x1010000020010;
	ppalist[3].ppa = 0x1010200020010;
	qblk_submit_test_ioread_async(qblk, ppalist, 4);
}

static void debugA(struct qblk *qblk, char *usrCommand)
{
	if ('1' == usrCommand[0])
		debugA1(qblk);
	else if ('2' == usrCommand[0])
		debugA2(qblk);
}
#endif

/* usage: "a @nr_chnls @nr_skip" */
static void qblk_set_activated(struct qblk *qblk,char *usrCommand)
{
	int nr_chnls, nr_skip;

	sscanf(usrCommand, "%d %d", &nr_chnls, &nr_skip);
	qblk->activated_channels = nr_chnls;
	qblk->nr_skip = nr_skip;
	pr_notice("QBLKe: set activated_channels as %d, nr_skip as %d\n",
				qblk->activated_channels, qblk->nr_skip);
}

/* usage: "e @chnl @lun @pl @blk @page @sector"*/
static void qblk_test_erase(struct qblk *qblk,char *usrCommand)
{
	struct ppa_addr ppa;
	int ch, lun, pl, blk, pg, sec;
	sscanf(usrCommand, "%d %d %d %d %d %d", &ch, &lun,
					&pl, &blk, &pg, &sec);
	ppa.g.ch = ch;
	ppa.g.lun =lun;
	ppa.g.pl = pl;
	ppa.g.blk = blk;
	ppa.g.pg = pg;
	ppa.g.sec = sec;
	pr_notice("%s, ppa = 0x%llx\n",
						__func__, ppa.ppa);

	qblk_blk_erase_test_async(qblk, ppa);
	return;
}

/* usage: "h @chnl @new_high"*/
static void qblk_set_rlhigh(struct qblk *qblk, char *usrCommand)
{
	int ch_idx, newhigh;
	struct qblk_per_chnl_rl *rl;

	sscanf(usrCommand, "%d%d", &ch_idx, &newhigh);
	rl = &qblk->ch[ch_idx].per_ch_rl;
	rl->high = newhigh;
	rl->high_pw = get_count_order(newhigh);
}


static void __print_line_info(struct qblk *qblk,
					int ch_idx, int line_id)
{
	struct ch_info *chi = &qblk->ch[ch_idx];
	struct qblk_line *line = &chi->lines[line_id];

	pr_notice("----%s,ch[%d] line[%d]-----\n",
						__func__, ch_idx, line_id);

	pr_notice("left_eblks(Blocks left for erasing)=%u\n", atomic_read(&line->left_eblks));
	pr_notice("left_seblks(Blocks left for sync erasing)=%u\n", atomic_read(&line->left_seblks));
#ifdef QBLKe_STAT_LINE_ERASECOUNT
	pr_notice("Erase Count=%lu\n", atomic64_read(&line->erase_count));
#endif
	pr_notice("left_msecs(Sectors left for mapping)=%d\n", line->left_msecs);
	pr_notice("vsc=%d\n", qblk_line_vsc(line));
	pr_notice("nr_valid_lbas=%u\n", line->nr_valid_lbas);
	pr_notice("smetaSsec[%llu] emetaSsec[%llu]\n",
				line->smeta_ssec, line->emeta_ssec);
	pr_notice("lineState=%s(%d)\n", ls_name[line->state],line->state);
	pr_notice("lineRef[%d]\n", kref_read(&line->ref));
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>>>>\n", __func__);
}

/* usage: "l @chnl @lineID"*/
static void qblk_printLineInfo(struct qblk *qblk, char *usrCommand)
{
	int ch_idx, line_id;

	sscanf(usrCommand, "%d %d", &ch_idx, &line_id);
	__print_line_info(qblk, ch_idx, line_id);
}

static void __print_rl_info(struct qblk *qblk, int chnl)
{
	struct qblk_per_chnl_rl *rl = &qblk->ch[chnl].per_ch_rl;
	unsigned long flags;

	pr_notice("----%s,ch[%d]-----\n",
						__func__, chnl);

	pr_notice("high[%u] rsv[%u]\n",
			rl->high, rl->rsv_blocks);
	pr_notice("free_blks[%u] free_usrBlks[%u]\n",
			atomic_read(&rl->free_blocks), atomic_read(&rl->free_user_blocks));
	spin_lock_irqsave(&rl->remain_secs_lock, flags);
	pr_notice("remain_secs=%u\n", rl->remain_secs);
	spin_unlock_irqrestore(&rl->remain_secs_lock, flags);
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>>>>\n", __func__);
}

/* usage: "r @chnl"*/
static void qblk_printRlInfo(struct qblk *qblk, char *usrCommand)
{
	int ch_idx;

	sscanf(usrCommand, "%d", &ch_idx);
	__print_rl_info(qblk, ch_idx);
}

/* usage: "se @max @min"*/
static void qblk_set_sema(struct qblk *qblk, char *usrCommand)
{
	int smax, smin;

	sscanf(usrCommand, "%d%d", &smax, &smin);
	WRITE_ONCE(qblk->sema_max, smax);
	WRITE_ONCE(qblk->sema_min, smin);
	pr_notice("%s, max %d, min %d\n",
				__func__, smax, smin);
}


static void __print_gc_info(struct qblk *qblk, int ch_idx)
{
	//struct qblk_gc *gc = &qblk->per_channel_gc[ch_idx];
	struct ch_info *chi = &qblk->ch[ch_idx];
	struct list_head *group_list;
	int gc_group;
	struct qblk_line *line;

	pr_notice("----%s,ch[%d]-----\n",
						__func__, ch_idx);
	pr_notice("qblk->gc_enabled[%d]\n",
			atomic_read(&qblk->gc_enabled)
			);
	for (gc_group = 0;
			gc_group < QBLK_GC_NR_LISTS;
			gc_group++) {
		group_list = chi->gc_lists[gc_group];
		if(list_empty(group_list)) {
			pr_notice("grouplist[%d] empty\n", gc_group);
			continue;
		}
		pr_notice("grouplist[%d] {\n", gc_group);
		list_for_each_entry(line, group_list, list) {
			pr_notice("<%u>\n", line->id);
		}
		pr_notice("}\n");
	}
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>>>>\n", __func__);
}

/* usage: "c @chnl"*/
static void qblk_printGcInfo(struct qblk *qblk,char *usrCommand)
{
	int ch_idx;

	sscanf(usrCommand, "%d", &ch_idx);
	__print_gc_info(qblk, ch_idx);
}

/* usage: "d @rb_index @nr_dummies"*/
static void qblk_testdummy(struct qblk *qblk, char *usrCommand)
{
	int rb_idx, ndummy;
	struct qblk_rb *rb;
	int mem;
	int i;
	int pos;
	struct qblk_rb_entry *entry;

	sscanf(usrCommand, "%d%d", &rb_idx, &ndummy);
	rb = qblk_get_rb_by_cpuid(qblk, rb_idx);
	spin_lock(&rb->w_lock);
	mem = READ_ONCE(rb->mem);
	for (i = 0; i < ndummy; i++) {
		int flags;

		pos = qblk_rb_wrap_pos(rb, mem + i);
		entry = qblk_rb_entry_by_index(qblk, rb, pos);
		entry->w_ctx.lba = entry->w_ctx.ppa.ppa = ADDR_EMPTY;
		flags = entry->w_ctx.flags | QBLK_WRITTEN_DATA;
		smp_store_release(&entry->w_ctx.flags, flags);
	}
	pos = qblk_rb_wrap_pos(rb, mem + i);
	smp_store_release(&rb->mem, pos);
	spin_unlock(&rb->w_lock);
}


/* usage: "g"*/
static void qblk_printGlobalRlInfo(struct qblk *qblk)
{
	struct qblk_rl *rl = &qblk->rl;

	pr_notice("----%s-----\n",
						__func__);

	pr_notice("nrsecs=%llu, total_blocks=%lu\n",
						rl->nr_secs,
						rl->total_blocks);
	pr_notice("rb_user_active=%d\n",
							rl->rb_user_active
							);
	pr_notice("rb_user_max=%d, rb_user_cnt=%d\n",
							atomic_read(&rl->rb_user_max),
							atomic_read(&rl->rb_user_cnt)
							);
	pr_notice("rb_gc_cnt=%d\n",
								atomic_read(&rl->rb_gc_cnt)
							);
	pr_notice("gc_active=0x%lx\n", *qblk->gc_active);
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>>>>\n", __func__);
}

/* usage: "m @lpn"*/
static void qblk_printMap(struct qblk *qblk,char *usrCommand)
{
	int lpn;
	struct ppa_addr ppa;

	sscanf(usrCommand, "%d", &lpn);
#ifdef QBLK_TRANSMAP_LOCK
	ppa = qblk_trans_map_get(qblk, lpn);
#else
	ppa = qblk_trans_map_atomic_get(qblk, lpn);
#endif
	pr_notice("%s:lpn[%d],ppn[0x%llx]\n",
						__func__, lpn, ppa.ppa);

}

static void __print_rb_info(struct qblk *qblk, int rb_idx)
{
	struct qblk_rb *rb = qblk_get_rb_by_cpuid(qblk, rb_idx);

	printRbStatus(qblk, rb, rb_idx);
}

/* usage: "b @rb_index"*/
static void qblk_printRbInfo(struct qblk *qblk, char *usrCommand)
{
	int rb_idx;

	sscanf(usrCommand, "%d", &rb_idx);
	__print_rb_info(qblk, rb_idx);
	
}

/* usage: "br @rb_index @entry_index"*/
static void qblk_debugBuffer_redundancy(struct qblk *qblk, char *usrCommand)
{
	int rb_idx;
	int entry_index;
	struct qblk_rb *rb;
	struct qblk_rb_entry *entry;

	sscanf(usrCommand, "%d%d", &rb_idx, &entry_index);

	rb = qblk_get_rb_by_cpuid(qblk, rb_idx);
	entry = qblk_rb_entry_by_index(qblk, rb, entry_index);
	pr_notice("%s, dataP=%p\n",
			__func__, entry->data);
	
}

/* usage: "q"*/
static void qblk_printMultiqueue_status(struct qblk *qblk)
{
	struct request_queue *queue = qblk->q;

	pr_notice("----%s  multiqueue_info-----\n", __func__);
	pr_notice("maxSeg=%u\n", queue_max_segments(queue));
}


/* usage: "s"*/
void qblk_printSInfo(struct qblk *qblk)
{
	int nr_chnl = qblk->nr_channels;
	int nr_rb = qblk->nr_queues;
	int i, j;
	struct ch_info *chi;
	long totalvsc, chnlvsc;

	pr_notice("----%s  rbinfo-----\n", __func__);
	pr_notice("*************************************\n");
	for (i=0;i<nr_rb;i++)
		__print_rb_info(qblk, i);
	pr_notice("----%s  global rl-----\n", __func__);
	pr_notice("*************************************\n");
	qblk_printGlobalRlInfo(qblk);
	pr_notice("----%s  per_ch rl+gc+line-----\n", __func__);
	pr_notice("*************************************\n");
	totalvsc = 0;
	for (i = 0;i < nr_chnl; i++) {
		struct qblk_line *dataline = qblk_line_get_data(chi);

		pr_notice("((((((((((chnl[%d]((((((((\n", i);
		chi = &qblk->ch[i];
		pr_notice("dataline=%d, datanext=%d\n",
							dataline?dataline->id:-1,
							chi->data_next?chi->data_next->id:-1);
		__print_rl_info(qblk, i);
		__print_gc_info(qblk, i);
		chnlvsc = 0;
		for (j = 0; j < chi->nr_lines; j++) {
			struct qblk_line *line = &chi->lines[j];
			int vsc;
			
			__print_line_info(qblk, i, j);
			vsc = qblk_line_vsc(line);
			if (vsc > 0) {
				chnlvsc += vsc;
				totalvsc += vsc;
			}
		}
		pr_notice(")))))chnl[%d] chnlvsc[%ld])))\n", i, chnlvsc);
	}
	pr_notice("<<<<<<<<<<<<%s>>totalvsc[%ld]>>>>>>>\n",
					__func__, totalvsc);
}

#ifdef QBLKe_DEBUG
static void qblk_tracker_work_fn(struct work_struct *work) {
	struct qblk_debug_tracker *tracker = container_of(to_delayed_work(work),
							struct qblk_debug_tracker, dw);
	struct qblk *qblk = tracker->qblk;
	struct qblk_rl *rl = &qblk->rl;

	tracker->print_count++;

	if (tracker->print_count==1) {
		tracker->usr_accepted = atomic_read(&rl->usr_accepted);
		tracker->gc_accepted = atomic_read(&rl->gc_accepted);
		tracker->usr_submitted = atomic_read(&rl->usr_attempt);
		tracker->gc_submitted = atomic_read(&rl->gc_attempt);
		tracker->usr_queued = atomic_read(&rl->usr_queued);
		tracker->gc_queued = atomic_read(&rl->gc_queued);
		tracker->gc_read = atomic_read(&rl->gc_read);
		tracker->gc_prewrite = atomic_read(&rl->gc_prewrite);
		tracker->gc_create_rq = atomic_read(&rl->gc_create_rq);
		tracker->gc_read_rq = atomic_read(&rl->gc_read_rq);
		tracker->gc_read_queued = atomic_read(&rl->gc_read_queued);
		tracker->gc_write_rq = atomic_read(&rl->gc_write_rq);
	} else {
		unsigned long usr_accepted = atomic_read(&rl->usr_accepted);
		unsigned long usr_attempt = atomic_read(&rl->usr_attempt);
		unsigned long gc_accepted = atomic_read(&rl->gc_accepted);
		unsigned long gc_attempt = atomic_read(&rl->gc_attempt);
		unsigned long usr_queued = atomic_read(&rl->usr_queued);
		unsigned long gc_queued = atomic_read(&rl->gc_queued);
		unsigned long gc_read = atomic_read(&rl->gc_read);
		unsigned long gc_prewrite = atomic_read(&rl->gc_prewrite);
		unsigned long gc_create_rq = atomic_read(&rl->gc_create_rq);
		unsigned long gc_read_rq = atomic_read(&rl->gc_read_rq);
		unsigned long gc_write_rq = atomic_read(&rl->gc_write_rq);
		unsigned long gc_read_queued = atomic_read(&rl->gc_read_queued);

		pr_notice("%s, print[%lu] usr_attempt[%lu] usr_accepted[%lu] usr_queued[%lu] gc_create[%lu] gc_read_rq[%lu] gc_read_queued[%lu] gc_read[%lu] gc_write_rq[%lu] gc_prewrite[%lu] gc_attempt[%lu] gc_accepted[%lu] gc_queued[%lu]\n",
					__func__, tracker->print_count,
					usr_attempt - tracker->usr_submitted,
					usr_accepted - tracker->usr_accepted,
					usr_queued - tracker->usr_queued,
					gc_create_rq - tracker->gc_create_rq,
					gc_read_rq - tracker->gc_read_rq,
					gc_read_queued - tracker->gc_read_queued,
					gc_read - tracker->gc_read,
					gc_write_rq - tracker->gc_write_rq,
					gc_prewrite - tracker->gc_prewrite,
					gc_attempt - tracker->gc_submitted,
					gc_accepted - tracker->gc_accepted,
					gc_queued - tracker->gc_queued);
		tracker->usr_submitted = usr_attempt;
		tracker->usr_accepted = usr_accepted;
		tracker->gc_submitted = gc_attempt;
		tracker->gc_accepted = gc_accepted;
		tracker->usr_queued = usr_queued;
		tracker->gc_queued = gc_queued;
		tracker->gc_read = gc_read;
		tracker->gc_prewrite = gc_prewrite;
		tracker->gc_create_rq = gc_create_rq;
		tracker->gc_read_rq = gc_read_rq;
		tracker->gc_write_rq = gc_write_rq;
		tracker->gc_read_queued = gc_read_queued;
		
	}
	if (tracker->print_count >= 10) {
		kfree(tracker);
	} else {
		schedule_delayed_work(&tracker->dw, 1000);
	}
}
#else
static void qblk_tracker_work_fn(struct work_struct *work) {
	struct qblk_debug_tracker *tracker = container_of(to_delayed_work(work),
								struct qblk_debug_tracker, dw);

	kfree(tracker);
}
#endif
/* usage: "tr"*/
void qblk_track(struct qblk *qblk) {
	struct qblk_debug_tracker *tracker = kmalloc(sizeof(*tracker), GFP_KERNEL);

	if (!tracker) {
		pr_err("%s, no mem\n", __func__);
		return;
	}
	tracker->print_count = 0;
	tracker->qblk = qblk;

	INIT_DELAYED_WORK(&tracker->dw, qblk_tracker_work_fn);
	schedule_delayed_work(&tracker->dw, 0);
}

/* usage: "x 1/0"*/
static void qblk_alterPrintRqOption(struct qblk *qblk,char *usrCommand)
{
	int newps;

	sscanf(usrCommand, "%d", &newps);

	qblk->print_rq_status = newps;
	return;
}

/* usage: "z"*/
static void qblk_printGeoInfo(struct qblk *qblk,char *usrCommand)
{
	struct nvm_geo *geo = &qblk->dev->geo;


	pr_notice("--------%s-----\n",
							__func__);
	pr_notice("max_rq_size[%d]\n", geo->max_rq_size);
	pr_notice("nr_chnls[%d] all_luns[%d] nr_luns[%d] nr_chks[%d]\n",
							geo->nr_chnls,
							geo->all_luns,
							geo->nr_luns,
							geo->nr_chks);
	pr_notice("ppaf:\n");
	pr_notice("blk_len[%d] blk_offset[%d] ch_len[%d] ch_offset[%d]\n",
		geo->ppaf.blk_len,
		geo->ppaf.blk_offset,
		geo->ppaf.ch_len,
		geo->ppaf.ch_offset);
	pr_notice("lun_len[%d] lun_offset[%d] pg_len[%d] pg_offset[%d]\n",
		geo->ppaf.lun_len,
		geo->ppaf.lun_offset,
		geo->ppaf.pg_len,
		geo->ppaf.pg_offset);
	pr_notice("pln_len[%d] pln_offset[%d] sect_len[%d] sect_offset[%d]\n",
		geo->ppaf.pln_len,
		geo->ppaf.pln_offset,
		geo->ppaf.sect_len,
		geo->ppaf.sect_offset);
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>\n",
							__func__);
}

void qblk_debug_printBioStatus(struct bio *bio) {
	int i;
	unsigned long *p;
	if(!bio){
		pr_notice("===printBioStatus===bio==NULL\n");
		return;
	}
	pr_notice("----------printBioStatus----------------\n");
	pr_notice("bi_opf=0x%x,__bi_cnt=%d,status=0x%x,vcnt=%d\n",bio->bi_opf,atomic_read(&bio->__bi_cnt),bio->bi_status,(int)bio->bi_vcnt);
							
	pr_notice("iter.sector=%lu,size=%u,idx=%u,done=%u,vecdone=%u\n",
		bio->bi_iter.bi_sector,bio->bi_iter.bi_size,bio->bi_iter.bi_idx,
		bio->bi_iter.bi_done,bio->bi_iter.bi_bvec_done);
								
	for(i=0;i<bio->bi_vcnt;i++){
		p = (unsigned long *)page_address(bio->bi_io_vec[i].bv_page);
		pr_notice("page=%p,p=0x%lx,len=0x%x,offset=0x%x\n",
										page_address(bio->bi_io_vec[i].bv_page),
										(unsigned long)p,
										bio->bi_io_vec[i].bv_len,
										bio->bi_io_vec[i].bv_offset);
									//pr_notice("data=%lx %lx %lx %lx\n",p[0],p[1],p[2],p[3]);
	}
								
	pr_notice("----------EndOf{PrintBioStatus}----------------\n");
							
}

#ifdef QBLKe_DEBUG

void qblk_debug_log(struct qblk *qblk,
							int value1, int value2,
							int value3, int value4)
{
	int cpu = smp_processor_id();
	struct qblk_printer_header *header =
				&qblk->printHeaders[cpu];
	int p;

	p = __atomic_add_unless(&header->p, 1, QBLK_PRINT_ENTRIES_PER_CPU);
	if (p < QBLK_PRINT_ENTRIES_PER_CPU) {
		struct qblk_print_entry *entry =
						&header->entries[p];

		entry->value1 = value1;
		entry->value2 = value2;
		entry->value3 = value3;
		entry->value4 = value4;
	}
}

static void qblk_debug_print(struct qblk *qblk, int cpu)
{
	struct qblk_printer_header *header =
				&qblk->printHeaders[cpu];
	int total = atomic_read(&header->p);
	int i;

	for (i = 0; i < total; i++) {
		struct qblk_print_entry *entry =
						&header->entries[i];

		pr_notice("cpu %d entry %d %d %d %d %d\n",
					cpu,
					i,
					entry->value1,
					entry->value2,
					entry->value3,
					entry->value4);
	}
}

static void qblk_debug_print_all(struct qblk *qblk)
{
	int totalcpus = num_possible_cpus();
	int i;

	for (i = 0; i < totalcpus; i++)
		qblk_debug_print(qblk, i);
}

static void qblk_debug_reset_all(struct qblk *qblk)
{
	int totalcpus = num_possible_cpus();
	int i;

	for (i = 0; i < totalcpus; i++) {
		struct qblk_printer_header *header =
				&qblk->printHeaders[i];

		atomic_set(&header->p, 0);
	}
}

#else

void qblk_debug_log(struct qblk *qblk,
							int value1, int value2,
							int value3, int value4)
{
}

static void qblk_debug_print_all(struct qblk *qblk)
{
}

static void qblk_debug_reset_all(struct qblk *qblk)
{
}

#endif

static ssize_t qblkDebug_write(struct file *file,
				const char __user *buffer,
				size_t count, loff_t *ppos)
{
	char usrCommand[512];
	int ret;
	int i;
	struct qblk *qblk = debugqblk;

	ret = copy_from_user(usrCommand, buffer,count);
	//pr_notice("command:%s",usrCommand);
	switch (usrCommand[0]) {
	case 'a':
		pr_notice("%s, a\n", __func__);
		qblk_set_activated(qblk, &usrCommand[1]);
		break;
	case 'b':
		pr_notice("%s, b\n", __func__);
		if (usrCommand[1] == 'r')
			qblk_debugBuffer_redundancy(qblk, &usrCommand[2]);
		else
			qblk_printRbInfo(qblk, &usrCommand[1]);
		break;
	case 'c':
		pr_notice("%s, c\n", __func__);
		qblk_printGcInfo(qblk, &usrCommand[1]);
		break;
	case 'd':
		pr_notice("%s, d\n", __func__);
		qblk_testdummy(qblk, &usrCommand[1]);
		break;
	case 'e':
		qblk_test_erase(qblk, &usrCommand[1]);
		break;
	case 'g':
		pr_notice("%s, g\n", __func__);
		qblk_printGlobalRlInfo(qblk);
		break;
	case 'h':
		pr_notice("%s, h\n", __func__);
		qblk_set_rlhigh(qblk, &usrCommand[1]);
		break;
	case 'p':
		if(usrCommand[1] == 'd') {
			pr_notice("%s, pd\n", __func__);
			for (i = 0; i < DEBUGCHNLS; i++)
				qblk_print_debug(qblk, i, 1);
			break;
		} else if (usrCommand[1] == 'a') {
			pr_notice("%s, ppa\n", __func__);
			qblk_debug_print_all(qblk);
			break;
		} else if (usrCommand[1] == 'r') {
			pr_notice("%s, ppr\n", __func__);
			qblk_debug_reset_all(qblk);
			break;
		}
	case 'q':
		pr_notice("%s, q\n", __func__);
		qblk_printMultiqueue_status(qblk);
		break;
	case 'm':
		pr_notice("%s, m\n", __func__);
		qblk_printMap(qblk, &usrCommand[1]);
		break;
	case 'l':
		pr_notice("%s, l\n", __func__);
		qblk_printLineInfo(qblk, &usrCommand[1]);
		break;
	case 'r':
		pr_notice("%s, r\n", __func__);
		qblk_printRlInfo(qblk, &usrCommand[1]);
		break;
	case 's':
		if (usrCommand[1] == 'e') {
			qblk_set_sema(qblk, &usrCommand[2]);
			break;
		}
		pr_notice("%s, s\n", __func__);
		qblk_printSInfo(qblk);
		break;
	case 't':
		if (usrCommand[1] == 'e') {
			pr_notice("%s, test\n", __func__);
			qblk_iotest(qblk);
			break;
		} else if (usrCommand[1] == 'r') {
			pr_notice("%s, track\n", __func__);
			qblk_track(qblk);
			break;
		}
	case 'x':
		pr_notice("%s, x\n", __func__);
		qblk_alterPrintRqOption(qblk, &usrCommand[1]);
		break;
	case 'y':
		pr_notice("%s, y\n", __func__);
		break;
	case 'z':
		pr_notice("%s, z\n", __func__);
		qblk_printGeoInfo(qblk, &usrCommand[1]);
		break;
	}
	return count;
}

static void qblk_fill_status(struct qblk *qblk, void *qblk_status)
{
	int nr_rb = qblk->nr_queues;
	int nr_chnls = qblk->nr_channels;
	int i, k;
	struct qblk_status_rb *prb;
	struct qblk_status_chnl *pchnl;
	struct qblk_rb *rb;
	struct qblk_per_chnl_rl *pch_rl;
	struct ch_info *chi;
	struct qblk_line *line;
	struct qblk_status_header *qblk_status_pheader;
	struct qblk_status_rb *qblk_status_prb;
	struct qblk_status_chnl *qblk_status_pchnl;

	qblk_status_pheader = qblk_status;
	qblk_status_prb = qblk_status + sizeof(struct qblk_status_header);
	qblk_status_pchnl = qblk_status + sizeof(struct qblk_status_header) + nr_rb * sizeof(struct qblk_status_rb);

	qblk_status_pheader->nr_chnl = nr_chnls;
	qblk_status_pheader->nr_rb = nr_rb;

	for (i = 0; i < nr_rb; i++) {
		prb = &qblk_status_prb[i];
		rb = qblk_get_rb_by_cpuid(qblk, i);

		prb->flush_point = READ_ONCE(rb->flush_point);
		prb->sync = READ_ONCE(rb->sync);
		prb->subm = READ_ONCE(rb->subm);
		prb->mem = READ_ONCE(rb->mem);
		prb->l2p_update = READ_ONCE(rb->l2p_update);
		for (k = 0; k < QBLK_RB_ACCOUNTING_ENTRIES; k++)
			prb->entries[k] = qblk_per_rb_account_get(qblk, i, k);
	}

	for (i = 0; i < nr_chnls; i++) {
		pchnl = &qblk_status_pchnl[i];
		chi = &qblk->ch[i];
		pch_rl = &chi->per_ch_rl;

		pchnl->chnl_state = pch_rl->chnl_state;
		line = qblk_line_get_data(chi);
		if (line)
			pchnl->current_data_line = line->id;
		else
			pchnl->current_data_line = -1;
		line = chi->data_next;
		if (line)
			pchnl->current_data_next = line->id;
		else
			pchnl->current_data_next = -1;
		
		pchnl->free_blocks = atomic_read(&pch_rl->free_blocks);
		pchnl->free_user_blocks = atomic_read(&pch_rl->free_user_blocks);
		pchnl->pch_rb_user_max = atomic_read(&pch_rl->pch_rb_user_max);
		spin_lock(&pch_rl->remain_secs_lock);
		pchnl->remain_secs = pch_rl->remain_secs;
		spin_unlock(&pch_rl->remain_secs_lock);
	}
}

static ssize_t qblkDebug_read(struct file *file, char __user *buffer, size_t count, loff_t *ppos)
{
	struct qblk *qblk = debugqblk;
	unsigned int status_size = qblk->status_size;
	void *qblk_status;
	int ret;

	qblk_status = kmalloc(status_size, GFP_KERNEL);
	if (!qblk_status)
		return 0;

	qblk_fill_status(qblk, qblk_status);
	if (count >= status_size)
		ret = copy_to_user(buffer, qblk_status, status_size);
	else
		ret = copy_to_user(buffer, qblk_status, count);
	kfree(qblk_status);
	if (ret)
		return EFAULT;
	return (count >= status_size)?status_size:count;
}

static const struct file_operations qblkDebug_proc_fops = {
  .owner = THIS_MODULE,
  .write = qblkDebug_write,
  .read = qblkDebug_read,
};

void qblk_debug_init(struct qblk *qblk)
{
	int i;
	unsigned int nr_rb;
	unsigned int status_size;
	unsigned int nr_chnls = qblk->nr_channels;
#ifdef DO_PER_RB_ACCOUNTING
	int k;
#endif
#if DEBUGCHNLS
	struct qblk_debug_header *header;
#endif

	debugqblk = qblk;
#ifdef QBLKe_DEBUG
	qblk->printHeaders = NULL;
#endif

	spin_lock_init(&qblk->debug_printing_lock);
	i = 0;

#if DEBUGCHNLS
	qblk->debugHeaders = kmalloc_array(DEBUGCHNLS,
			sizeof(*qblk->debugHeaders), GFP_KERNEL);
	if (!qblk->debugHeaders)
		return;
	for (i = 0; i < DEBUGCHNLS; i++) {
		header = &qblk->debugHeaders[i];
		spin_lock_init(&header->lock);
		header->p = 0;
	}
	pr_notice("%s, DEBUGCHNLS %u, entries per DEBUGCHNLS %u\n",
			__func__, DEBUGCHNLS, QBLK_DEBUG_ENTRIES_PER_CHNL);
#endif

	nr_rb = qblk->nr_queues;
#ifdef QBLKe_DEBUG

	qblk->printHeaders = kmalloc_array(nr_rb,
			sizeof(*qblk->printHeaders), GFP_KERNEL);
	if (!qblk->printHeaders)
		goto out1;
	for (i = 0; i < nr_rb; i++)
		atomic_set(&qblk->printHeaders[i].p, 0);

	pr_notice("%s, nr_CPUs %u, entries per CPU %u\n",
			__func__, nr_rb, QBLK_PRINT_ENTRIES_PER_CPU);
#endif
	
	qblk->debugstart = 1;
	qblk->print_rq_status = 0;

	qblk->status_size = status_size = sizeof(struct qblk_status_header) +
					nr_rb * sizeof(struct qblk_status_rb) +
					nr_chnls * sizeof(struct qblk_status_chnl);
	//pr_notice("%s, status_size=%u\n", __func__, status_size);

#ifdef DO_PER_RB_ACCOUNTING
	qblk->prb_accounting = alloc_percpu(struct qblk_per_rb_accounting);
	if (!qblk->prb_accounting)
		goto out2;
	for (i = 0; i < nr_rb; i++)
		for (k = 0; k < QBLK_RB_ACCOUNTING_ENTRIES; k++)
			qblk_per_rb_account_set(qblk, i, k, 0);
#endif

	spin_lock_init(&debug_printlock);
	proc_create("qblkDebug", 0, NULL, &qblkDebug_proc_fops);
	return;

#ifdef DO_PER_RB_ACCOUNTING
	free_percpu(qblk->prb_accounting);
out2:
#endif

#ifdef QBLKe_DEBUG

	qblk->printHeaders = NULL;
	kfree(qblk->printHeaders);
out1:
#endif

	qblk->debugHeaders = NULL;
	kfree(qblk->debugHeaders);
}

void qblk_debug_exit()
{
	remove_proc_entry("qblkDebug", NULL);
#ifdef DO_PER_RB_ACCOUNTING
	free_percpu(debugqblk->prb_accounting);
#endif

#ifdef QBLKe_DEBUG
	kfree(debugqblk->printHeaders);
	debugqblk->printHeaders = NULL;
#endif

	kfree(debugqblk->debugHeaders);
	debugqblk->debugHeaders = NULL;
}

#ifdef MONITOR_TIME
void qblk_printTimeMonotonic(const char *ch, int line)
{
	struct timespec ts;

	getrawmonotonic(&ts);
	pr_notice("%s line %d s %ld ns %ld\n",
					ch,
					line,
					ts.tv_sec,
					ts.tv_nsec);
}
#else
void qblk_printTimeMonotonic(const char *ch, int line)
{
}
#endif

