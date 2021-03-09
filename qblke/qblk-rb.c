#include <linux/circ_buf.h>

#include "qblk.h"

//declaration lock
static DECLARE_RWSEM(qblk_rb_lock);

static unsigned long *bitmap_alloc(unsigned int nbits, gfp_t flags)
{
	return kmalloc_array(BITS_TO_LONGS(nbits), sizeof(unsigned long),
			     flags);
}

static unsigned long *bitmap_zalloc(unsigned int nbits, gfp_t flags)
{
	return bitmap_alloc(nbits, flags | __GFP_ZERO);
}

void bitmap_free(const unsigned long *bitmap)
{
	kfree(bitmap);
}

unsigned int qblk_rb_sync_init(struct qblk_rb *rb, unsigned long *flags)
	__acquires(&rb->s_lock)
{
	if (flags)
		spin_lock_irqsave(&rb->s_lock, *flags);
	else
		spin_lock_irq(&rb->s_lock);

	//return rb->sync;
	return READ_ONCE(rb->sync);
}

void qblk_rb_sync_end(struct qblk_rb *rb, unsigned long *flags)
	__releases(&rb->s_lock)
{
	lockdep_assert_held(&rb->s_lock);

	if (flags)
		spin_unlock_irqrestore(&rb->s_lock, *flags);
	else
		spin_unlock_irq(&rb->s_lock);
}

unsigned int qblk_rb_sync_advance(struct qblk *qblk,
					struct qblk_rb *rb, unsigned int nr_entries)
{
	unsigned int sync;
	unsigned int has_flushpoint;

	lockdep_assert_held(&rb->s_lock);

	sync = READ_ONCE(rb->sync);
	spin_lock(&rb->fp_write_lock);
	has_flushpoint = atomic_read_acquire(&rb->has_flushpoint);

	//pr_notice("%s,rb[%u]sync=%u,flushpoint=%u,nrEntry[%u]\n",
	//			__func__, rb->rb_index,
	//			sync, flush_point, nr_entries);

	if (has_flushpoint) {
		unsigned int secs_to_flush;
		unsigned int flush_point = READ_ONCE(rb->flush_point);
		
		secs_to_flush = qblk_rb_ring_count(flush_point, sync);
		if (secs_to_flush < nr_entries) {
			/* Protect flush points */
			atomic_set_release(&rb->has_flushpoint, 0);
		}
	}
	spin_unlock(&rb->fp_write_lock);

	sync += nr_entries;

	/* Protect from counts */
	smp_store_release(&rb->sync, sync);
	//pr_notice("%s,sync=%u stored\n", __func__, sync);

	return sync;
}

static struct qblk_persist_work *qblk_persist_work_alloc_init(struct request *req,
																unsigned int nr_rb)
{
	unsigned int i;

	struct qblk_persist_work *persist_work =
			(struct qblk_persist_work *)kmalloc(sizeof(*persist_work), GFP_ATOMIC);

	if (!persist_work)
		return NULL;
	spin_lock_init(&persist_work->lock);
	persist_work->req = req;
	persist_work->persist_bm = bitmap_zalloc(nr_rb, GFP_ATOMIC);
	if (!persist_work->persist_bm)
		goto errOut;

	persist_work->per_rb_pws = kmalloc_array(nr_rb,
								sizeof(struct qblk_per_rb_pw),
								GFP_ATOMIC);
	if (!persist_work->per_rb_pws)
		goto errOut2;

	for (i = 0; i < nr_rb; i++)
		persist_work->per_rb_pws[i].pw = persist_work;

	return persist_work;
errOut2:
	bitmap_free(persist_work->persist_bm);
errOut:
	kfree(persist_work);
	return NULL;
}

void qblk_persist_work_release(struct qblk_persist_work *persist_work)
{
	kvfree(persist_work->per_rb_pws);
	bitmap_free(persist_work->persist_bm);
	kvfree(persist_work);
}

/*
 * Buffer count is calculated with respect to the submission entry signaling the
 * entries that are available to send to the media
 */
unsigned int qblk_rb_read_count(struct qblk *qblk, struct qblk_rb *rb)
{
	unsigned int mem = READ_ONCE(rb->mem);
	unsigned int subm = READ_ONCE(rb->subm);
	//unsigned int perrb_size = READ_ONCE(qblk->perrb_size);

	return qblk_rb_ring_count(mem, subm);
}

unsigned int qblk_rb_sync_count(struct qblk *qblk, struct qblk_rb *rb)
{
	unsigned int mem = READ_ONCE(rb->mem);
	unsigned int sync = READ_ONCE(rb->sync);
	//unsigned int perrb_size = READ_ONCE(qblk->perrb_size);

	return qblk_rb_ring_count(mem, sync);
}

unsigned int qblk_rb_read_commit(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int nr_entries)
{
	unsigned int subm, ret;

	ret = subm = READ_ONCE(rb->subm);
	subm += nr_entries;

	/* Commit read means updating submission pointer */
	smp_store_release(&rb->subm, subm);

	return ret;
}

struct qblk_w_ctx *qblk_rb_w_ctx(struct qblk *qblk, struct qblk_rb *rb, unsigned int pos)
{
	struct qblk_rb_entry *p = qblk_rb_entry_by_index(qblk, rb, pos);

	return &p->w_ctx;
}

/* Calculate how many sectors to submit up to the current flush point. */
unsigned int qblk_rb_flush_point_count(struct qblk *qblk,
					struct qblk_rb *rb, unsigned int flush_point)
{
	unsigned int subm, sync;
	unsigned int submitted, to_flush;
	//unsigned int perrb_size = qblk->perrb_size;

	/* Protect syncs */
	sync = smp_load_acquire(&rb->sync);

	subm = READ_ONCE(rb->subm);
	submitted = qblk_rb_ring_count(subm, sync);

	/* The sync point itself counts as a sector to sync */
	to_flush = qblk_rb_ring_count(flush_point, sync) + 1;

	return (submitted < to_flush) ? (to_flush - submitted) : 0;
}

void qblk_rb_set_flush_point(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int new_point)
{
	unsigned int sync;
	unsigned int old_to_flush, new_to_flush;
	unsigned int flush_point;
	//unsigned int rbsize = qblk->perrb_size;

	lockdep_assert_held(&rb->fp_write_lock);

	if (!atomic_read_acquire(&rb->has_flushpoint)) {
		smp_store_release(&rb->flush_point, new_point);
		atomic_set_release(&rb->has_flushpoint, 1);
		return;
	}

	flush_point = smp_load_acquire(&rb->flush_point);
	sync = smp_load_acquire(&rb->sync);
	old_to_flush = qblk_rb_ring_count(flush_point, sync);
	new_to_flush = qblk_rb_ring_count(new_point, sync);

	if (new_to_flush > old_to_flush)
		smp_store_release(&rb->flush_point, new_point);
}


static void clean_wctx(struct qblk_w_ctx *w_ctx)
{
	int flags;
	int nr_retry = 0;

try:
	flags = READ_ONCE(w_ctx->flags);
	if (!(flags & (QBLK_SUBMITTED_ENTRY | QBLK_WRITABLE_ENTRY))) {
		nr_retry++;
 		if (nr_retry > 1024) {
			pr_err("%s, retry too much, flags=0x%x\n",
						__func__, flags);
			goto force_clean;
 		}
		goto try;
	}

force_clean:
	/* Release flags on context. Protect from writes and reads */
	smp_store_release(&w_ctx->flags, QBLK_WRITABLE_ENTRY);
	qblk_ppa_set_empty(&w_ctx->ppa);
	w_ctx->lba = ADDR_EMPTY;
}

/* When we get here, it's garanteed that
 * we've already had enough space from l2p_update to sync.
 * This is achieved by __qblk_rb_may_write()'s first check.
 * As a result, there is no need to check for the rb->sync pointer.
 */
int __qblk_rb_update_l2p(struct qblk *qblk, struct qblk_rb *rb, unsigned int to_update)
{
	struct qblk_line *line;
	struct qblk_rb_entry *entry;
	struct qblk_w_ctx *w_ctx;
	unsigned int user_io = 0, gc_io = 0;
	unsigned int i;
	int flags;

	for (i = 0; i < to_update; i++) {
		unsigned int l2p_update = READ_ONCE(rb->l2p_update);

		entry = qblk_rb_entry_by_index(qblk, rb, l2p_update);
		w_ctx = &entry->w_ctx;

		flags = READ_ONCE(entry->w_ctx.flags);
		if (flags & QBLK_IOTYPE_USER)
			user_io++;
		else if (flags & QBLK_IOTYPE_GC)
			gc_io++;

		qblk_update_map_dev(qblk, w_ctx->lba, w_ctx->ppa,
							entry->cacheline);
		if (!qblk_ppa_empty(w_ctx->ppa)){
			line = qblk_ppa_to_structline(qblk, w_ctx->ppa);
			kref_put(&line->ref, qblk_line_put);
		}
		//pr_notice("%s,put the reference of line[%u]\n",__func__,line->id);
		clean_wctx(w_ctx);

		l2p_update++;

		smp_store_release(&rb->l2p_update, l2p_update);
	}

	qblk_rl_out(qblk,
			user_io, gc_io);

	return 0;
}


/*
 * When we move the l2p_update pointer, we update the l2p table - lookups will
 * point to the physical address instead of to the cacheline in the write buffer
 * from this moment on.
 */
int qblk_rb_update_l2p(struct qblk *qblk, struct qblk_rb *rb, unsigned int nr_entries,
			      unsigned int mem, unsigned int sync)
{
	unsigned int space, count;
	int ret = 0;

	lockdep_assert_held(&rb->w_lock);

	/* Update l2p only as buffer entries are being overwritten */
	space = qblk_rb_ring_space(mem, READ_ONCE(rb->l2p_update), qblk->perrb_size);
	//pr_notice("%s, space[%u] nrentries[%u] perrb_size[%u]\n",
	//			__func__, space, nr_entries, qblk->perrb_size);
	if (space > nr_entries)
		goto out;

	count = nr_entries - space;
	/* l2p_update used exclusively under rb->w_lock */
	ret = __qblk_rb_update_l2p(qblk, rb, count);

out:
	return ret;
}

/*
 * Update the l2p entry for all sectors stored on the write buffer. This means
 * that all future lookups to the l2p table will point to a device address, not
 * to the cacheline in the write buffer.
 */
static void qblk_rb_sync_l2p(struct qblk *qblk, struct qblk_rb *rb)
{
	unsigned int sync;
	unsigned int l2p_update;
	unsigned int to_update;

	spin_lock(&rb->w_lock);

	/* Protect from reads and writes */
	sync = smp_load_acquire(&rb->sync);
	l2p_update = READ_ONCE(rb->l2p_update);

	to_update = qblk_rb_ring_count(sync, l2p_update);
	__qblk_rb_update_l2p(qblk, rb, to_update);

	spin_unlock(&rb->w_lock);
}

void qblk_rb_sync_all_l2p(struct qblk *qblk)
{
	unsigned int queue_count = qblk->nr_queues;
	while (queue_count--)
		qblk_rb_sync_l2p(qblk, qblk_get_rb_by_cpuid(qblk, queue_count));
}

/* Check whether the rb have enough space for the comming request.
 * Return:
 * 0: space is sufficient.
 * n: space is in-sufficient.
 *    n = rb size;
 */
static int __qblk_rb_maynot_write(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int nr_entries)
{
	unsigned int sync = READ_ONCE(rb->sync);
	unsigned int mem = READ_ONCE(rb->mem);

	if (qblk_rb_ring_space(mem, sync, qblk->perrb_size) < nr_entries)
		return qblk->perrb_size;

	qblk_rb_update_l2p(qblk, rb, nr_entries, mem, sync);
	return 0;
}

static void qblk_rb_persist_point_set(struct qblk *qblk,
					unsigned int rb_index,
					struct qblk_rb *rb,
					struct qblk_persist_work *persist_work)
{
	struct qblk_rb_entry *entry;
	unsigned int sync, persist_point;
	unsigned long flags;
	unsigned int pos;

	qblk_rb_sync_init(rb, &flags);
	spin_lock(&rb->fp_write_lock);
	pos = READ_ONCE(rb->mem);
	sync = READ_ONCE(rb->sync);
	
	//pr_notice("%s, rb(%u) pos=%u sync=%u\n",
	//			__func__, rb->rb_index, pos, sync);

	if (pos == sync) {
		spin_unlock(&rb->fp_write_lock);
		qblk_end_persist_point(rb, qblk, persist_work);
		qblk_rb_sync_end(rb, &flags);
		return;
	}

	persist_point = pos - 1;
	entry = qblk_rb_entry_by_index(qblk, rb, persist_point);

	/* Here, since we've already hold the rb->s_lock,
	 * the draining thread will not be able to move the
	 * sync pointer. Thus, we're save to set
	 * any entry's persist list.
	 */

	list_add(&persist_work->per_rb_pws[rb_index].list , &entry->w_ctx.persist_list);
	qblk_rb_set_flush_point(qblk, rb, persist_point);
	spin_unlock(&rb->fp_write_lock);
	qblk_rb_sync_end(rb, &flags);
}

static int qblk_rb_maynot_write(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int nr_entries,
			    unsigned int *pos)
{
	unsigned int mem = READ_ONCE(rb->mem);
	int ret;

	*pos = mem;

	ret = __qblk_rb_maynot_write(qblk, rb, nr_entries);
	if (ret)
		return ret;

	/* Now we'll move the rb->mem pointer. */
	mem += nr_entries;

	smp_store_release(&rb->mem, mem);
	return 0;
}

static int qblk_rb_maynot_write_flush(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int nr_entries,
				unsigned int *pos, struct bio *bio,
				struct request *req)
{
	unsigned int old_mem, mem;
	int ret = 0;
	unsigned int request_flags = req->cmd_flags;

	*pos = old_mem = READ_ONCE(rb->mem);

	ret = __qblk_rb_maynot_write(qblk, rb, nr_entries);
	if (ret)
		return ret;

	/* Now we'll move the rb->mem pointer. */
	mem = *pos + nr_entries;

	/* Blk-mq guarantees that we'll not find REQ_PREFLUSH here */
	WARN_ON(request_flags & REQ_PREFLUSH);
#ifndef IGNORE_FUA
	if (request_flags & REQ_FUA) {
		unsigned int fua_point =
			qblk_rb_wrap_pos(rb, old_mem + nr_entries -1);
		unsigned long flags;
		struct qblk_rb_entry *entry;

		/* __qblk_rb_maynot_write() guarantees that we have enough space for
		 * this req.
		 */
		entry = qblk_rb_entry_by_index(qblk, rb, fua_point);
		entry->w_ctx.fua_req = req;
		spin_lock_irqsave(&rb->fp_write_lock, flags);
		qblk_rb_set_flush_point(qblk, rb, fua_point);
		spin_unlock_irqrestore(&rb->fp_write_lock, flags);

		//pr_notice("%s, FUA!\n", __func__);

		ret = -1;//Don't end this request because the data is not persisted yet.
	}
#endif

	smp_store_release(&rb->mem, mem);
		
	return ret;
}

/*
 * Atomically check that (i) there is space on the write buffer for the
 * incoming I/O, and (ii) the current I/O type has enough budget in the write
 * buffer (rate-limiter).
 * Return value:
 * 0: OK
 * 1: Rate limiter may not insert
 * >1: Not enough space for ring buffer. See __qblk_rb_maynot_write();
 * -1: OK, but this is an FUA request, don't finish this request.
 * -2: Err
 */
static int qblk_rb_may_write_user(struct qblk *qblk,
				unsigned int rbid,
				struct qblk_rb *rb, struct bio *bio,
				unsigned int nr_entries, unsigned int *pos,
				struct request *req)
{
	int ret;

	if (qblk_rl_user_maynot_insert(qblk, nr_entries))
		return 1;

#ifdef QBLKe_DEBUG
	atomic_add(nr_entries, &qblk->rl.usr_accepted);
#endif

	spin_lock(&rb->w_lock);
	ret = qblk_rb_maynot_write_flush(qblk, rb, nr_entries, pos, bio, req);
	if (ret) {
		spin_unlock(&rb->w_lock);
		return ret;
	}

	qblk_rl_user_in(&qblk->rl, nr_entries);
	spin_unlock(&rb->w_lock);

	//pr_notice("%s:ret=%d\n",__func__,io_ret);
#ifdef QBLKe_DEBUG
	atomic_add(nr_entries, &qblk->rl.usr_queued);
#endif

	return 0;
}

/*
 * Write @nr_entries to ring buffer from @data buffer if there is enough space.
 * Typically, 4KB data chunks coming from a bio will be copied to the ring
 * buffer, thus the write will fail if not all incoming data can be copied.
 *
 */
static void __qblk_rb_write_entry(struct qblk_rb *rb, void *data,
				  struct qblk_w_ctx w_ctx,
				  struct qblk_rb_entry *entry)
{
	memcpy(entry->data, data, rb->seg_size);

	entry->w_ctx.lba = w_ctx.lba;
	entry->w_ctx.ppa = w_ctx.ppa;
}

static void qblk_rb_write_entry_user(struct qblk *qblk,
				struct qblk_rb *rb, void *data,
				struct qblk_w_ctx w_ctx, unsigned int ring_pos)
{
	struct qblk_rb_entry *entry;
	int flags;

	entry = qblk_rb_entry_by_index(qblk, rb, ring_pos);
	flags = READ_ONCE(entry->w_ctx.flags);

	//pr_notice("%s,ringpos=%u\n",__func__,ring_pos);
	//printPageSample(data);

	__qblk_rb_write_entry(rb, data, w_ctx, entry);

	qblk_update_map_cache(qblk, rb, w_ctx.lba, entry->cacheline);
	flags = w_ctx.flags | QBLK_WRITTEN_DATA;

	/* Release flags on write context. Protect from writes */
	smp_store_release(&entry->w_ctx.flags, flags);
}

static void qblk_rb_write_entry_gc(struct qblk *qblk,
				struct qblk_rb *rb, void *data,
			    struct qblk_w_ctx w_ctx, struct qblk_line *line,
			    u64 paddr, unsigned int ring_pos)
{
	struct qblk_rb_entry *entry;
	int flags;

	entry = qblk_rb_entry_by_index(qblk, rb, ring_pos);
	flags = READ_ONCE(entry->w_ctx.flags);
#ifdef CONFIG_NVM_DEBUG
	/* Caller must guarantee that the entry is free */
	BUG_ON(!(flags & QBLK_WRITABLE_ENTRY));
#endif

	__qblk_rb_write_entry(rb, data, w_ctx, entry);


	if (!qblk_update_map_gc(qblk, rb, w_ctx.lba, entry->cacheline, line, paddr))
		entry->w_ctx.lba = ADDR_EMPTY;

	flags = w_ctx.flags | QBLK_WRITTEN_DATA;

	/* Release flags on write context. Protect from writes */
	smp_store_release(&entry->w_ctx.flags, flags);
}

void qblk_rb_data_free(struct qblk_rb *rb)
{
	unsigned long flags;

	//Free the rb entries and rb->p_entries. Make sure to release all the memories
	spin_lock_irqsave(&rb->w_lock, flags);
	if (rb->rb_entries)
		kvfree(rb->rb_entries);
	spin_unlock_irqrestore(&rb->w_lock, flags);
}

static void qblk_rb_entry_init(struct qblk_rb *rb, struct qblk_rb_entry *entry,
									void *base, int i)
{
	entry->data = base + (i * rb->seg_size);
	entry->cacheline = qblk_cacheline_to_addr(rb->rb_index, i);
	entry->w_ctx.flags = QBLK_WRITABLE_ENTRY;
	INIT_LIST_HEAD(&entry->w_ctx.persist_list);
	entry->w_ctx.fua_req = NULL;
}

/* Return 0 if succeed.
 */
unsigned long qblk_alloc_mem_to_rb(struct qblk *qblk,
				struct qblk_rb *rb,
				unsigned int nr_entries)
{
	struct qblk_rb_entry *entries;
	int i;
	void *base;

	//pr_notice("%s, rb[%u] allocate %d entries start from [%d]\n",
	//				__func__, rb->rb_index, nr_entries, startEntry);

	rb->rb_entries = entries = kmalloc_array(nr_entries, sizeof(*entries), GFP_KERNEL|__GFP_ZERO);
	if (!entries)
		return -ENOMEM;

	base = (void *)__get_free_pages(GFP_KERNEL, get_count_order(nr_entries));
	if (!base)
		goto errout;

	for (i = 0; i < nr_entries; i++) {
		struct qblk_rb_entry *entry =
			&entries[i];

		qblk_rb_entry_init(rb, entry, base, i);
	}

	return 0;
	free_pages((unsigned long)base, get_count_order(nr_entries));
errout:
	kfree(entries);
	return -ENOMEM;
}

/* Caller must guarantee @init_entries is an integer multiple of QBLK_RB_ALLOC_SIZE. */
int qblk_init_percpu_rb(struct qblk *qblk, struct qblk_rb *rb,
		unsigned int rbIndex, unsigned long rb_entries, int sec_size)
{
	unsigned long ret;

	//pr_notice("%s, rbIndex[%u], init_entries[%lu]\n",
	//			__func__, rbIndex, init_entries);

	WARN_ON(1 << get_count_order(rb_entries) != rb_entries);

	down_write(&qblk_rb_lock);
	rb->qblk = qblk;
	rb->rb_index = rbIndex;
	rb->seg_size = sec_size;
	rb->mem = rb->subm = rb->sync = rb->l2p_update = rb->flush_point = 0;
	atomic_set(&rb->has_flushpoint, 0);

	spin_lock_init(&rb->w_lock);
	spin_lock_init(&rb->s_lock);
	spin_lock_init(&rb->fp_write_lock);

	ret = qblk_alloc_mem_to_rb(qblk, rb, rb_entries);
	if (ret) {
		pr_notice("%s, cannot alloc free pages to rb[%u], needed=%lu\n",
					__func__, rbIndex, rb_entries);
		goto errout1;
	}

	up_write(&qblk_rb_lock);

	//pr_notice("%s, rb[%u] init finished with %lu entries\n",
	//			__func__, rbIndex, rb_entries);

	return 0;

errout1:
	up_write(&qblk_rb_lock);
	return -ENOMEM;
}

int qblk_rb_tear_down_check(struct qblk *qblk, struct qblk_rb *rb)
{
	struct qblk_rb_entry *entry;
	int i;
	int ret = 0;
	unsigned int rbsize = qblk->perrb_size;

	spin_lock(&rb->w_lock);
	spin_lock(&rb->s_lock);

	if ((rb->mem == rb->subm) && (rb->subm == rb->sync) &&
				(rb->sync == rb->l2p_update) &&
				!atomic_read(&rb->has_flushpoint)) {
		goto out;
	}

	if (!rb->rb_entries) {
		ret = 1;
		goto out;
	}

	for (i = 0; i < rbsize; i++) {
		entry = qblk_rb_entry_by_index(qblk, rb, i);

		if (!entry->data) {
			ret = 1;
			goto out;
		}
	}

out:
	spin_unlock(&rb->s_lock);
	spin_unlock(&rb->w_lock);
	return ret;
}

int qblk_rb_pos_oob(struct qblk *qblk, struct qblk_rb *rb, u64 pos)
{
	return (pos >= qblk->perrb_size);
}

void printRbStatus(struct qblk *qblk, struct qblk_rb *ringBuffer, unsigned int rbIndex)
{
	int i;

	spin_lock(&ringBuffer->w_lock);
	pr_notice("''''''''''''''%s''''''''''''''\n",	__func__);
	pr_notice("rb[%u] status: flushpoint=%u, l2pupdate=%u, mem=%u,subm=%u,sync=%u\n",
		rbIndex, READ_ONCE(ringBuffer->flush_point),
		READ_ONCE(ringBuffer->l2p_update),
		READ_ONCE(ringBuffer->mem),
		READ_ONCE(ringBuffer->subm),
		READ_ONCE(ringBuffer->sync));
	for (i = 0; i < 8; i++) {
		struct qblk_rb_entry *p = qblk_rb_entry_by_index(qblk, ringBuffer, i);
		pr_notice("[%d]:cacheline=0x%llx, wctxflags=0x%x, wctxlba=0x%llx, wctxppa=0x%llx\n",
			i,
			p->cacheline.ppa,
			p->w_ctx.flags,
			p->w_ctx.lba,
			p->w_ctx.ppa.ppa);
	}
	pr_notice("rb ring space: %d\n",
					qblk_rb_ring_space(ringBuffer->mem,
						ringBuffer->sync,
						ringBuffer->qblk->perrb_size));
	
	//pr_notice("%s^^^^^^^^^^^^^END^^^^^^^^^^^^^^^^^^^^^\n",
	//													__func__);
	spin_unlock(&ringBuffer->w_lock);
}

blk_status_t qblk_rq_write_to_cache(struct qblk *qblk,
				struct qblk_queue *pq,
				struct request *req,
				unsigned long flags)
{
	struct request_queue *q = req->q;
	struct qblk_w_ctx w_ctx;
	unsigned int bpos, pos;
	int i;
	int writeUserRet;
	struct bio *bio, *newbio;
	unsigned int rbIndex = pq->hctx_idx;
	struct qblk_rb *ringBuffer = qblk_get_rb_by_cpuid(qblk, rbIndex);
	sector_t lba;
	int nr_entries;
	int max_payload_pgs;
	int endreq = 1;

	__rq_for_each_bio(bio, req) {
		lba = qblk_get_lba(bio);
		nr_entries = qblk_get_secs(bio);

		//pr_notice("write command, rbIndex=%u, lba=%lu, nrEntries=%d\n",rbIndex,lba,nr_entries);

		/* Update the write buffer head (mem) with the entries that we can
		 * write. The write in itself cannot fail, so there is no need to
		 * rollback from here on.
		 */
		writeUserRet = qblk_rb_may_write_user(qblk, rbIndex, ringBuffer, bio, nr_entries, &bpos, req);
		qblk_per_rb_account(qblk, rbIndex, QBLK_USR_SUBMITTED, nr_entries);
		switch (writeUserRet) {
		case -1:
			endreq = 0;
		case 0:
			qblk_per_rb_account(qblk, rbIndex, QBLK_USR_ACCEPTED, nr_entries);
			break;
		case -2:
			//err
			return BLK_STS_IOERR;
		case 1:
			//pr_notice("%s,return with 1(Rate limiter may not insert)\n", __func__);
			return BLK_STS_RESOURCE;
		default:
			/* In case of not enough space inside ring buffer,
			 * we should check whether our requested nr_engries
			 * is too large.
			 */
			//pr_notice("%s,return with %d\n",__func__, writeUserRet);

			//pr_notice("%s,return with BLK_STS_RESOURCE\n",__func__);
			//printRbStatus(ringBuffer, rbIndex);

			max_payload_pgs = writeUserRet - qblk->min_write_pgs;

			/* We only split bios that exceed ringBuffer's capacity */
			if (nr_entries > max_payload_pgs) {
				//pr_notice("%s, split bio-maxPayloadPgs, %d\n", __func__, max_payload_pgs);
				max_payload_pgs >>= 1;
				//pr_notice("%s, split bio-actualSplit, %d\n", __func__, max_payload_pgs);
				
				newbio = bio_split(bio,
							max_payload_pgs << 3,
							GFP_ATOMIC, q->bio_split);
				//bio_chain(newbio, bio);
				newbio->bi_opf |= REQ_NOMERGE;
				newbio->bi_next = bio->bi_next;
				bio->bi_next = newbio;
				//qblk_debug_printBioStatus(newbio);
				//qblk_debug_printBioStatus(bio);
			}

			return BLK_STS_RESOURCE;
		
		}
		//printRbStatus(ringBuffer,rbIndex);
		if (unlikely(!bio_has_data(bio)))
			continue;

		qblk_printTimeMonotonic(__func__,
				qblk_rb_ring_space(READ_ONCE(ringBuffer->mem),
				READ_ONCE(ringBuffer->sync),
				qblk->perrb_size));

		qblk_ppa_set_empty(&w_ctx.ppa);
		w_ctx.flags = flags;

		for (i = 0; i < nr_entries; i++) {
			void *data = bio_data(bio);

			w_ctx.lba = lba + i;
			//pr_notice("%s:wctx[%d].lba=0x%llx\n", __func__, i, w_ctx.lba);

			pos = qblk_rb_wrap_pos(ringBuffer, bpos + i);
			qblk_rb_write_entry_user(qblk, ringBuffer, data, w_ctx, pos);

			bio_advance(bio, QBLK_EXPOSED_PAGE_SIZE);
		}

		qblk_printTimeMonotonic(__func__, __LINE__);

/*
#ifdef CONFIG_NVM_DEBUG
		atomic_long_add(nr_entries, &qblk->inflight_writes);
		atomic_long_add(nr_entries, &qblk->req_writes);
#endif
*/
		//break;
	}

	if (endreq) {
		//pr_notice("%s,endrequest with BLK_STS_OK,lba=%lu, nrEntries=%d\n",__func__,lba,nr_entries);
		blk_mq_end_request(req, BLK_STS_OK);
	}
	
	qblk_write_should_kick(qblk, rbIndex, (req->cmd_flags & REQ_NOMERGE)?1:0);
	//pr_notice("%s,ret=%d\n", __func__, ret);
	return BLK_STS_OK;
}

/*
 * Blk-mq serializes flush requests on each cpu. But flush requests
 * from different CPUs can be issued concurrently.
 * Since the sematic of flush request requires the driver to persist
 * all data in the volatile buffer, QBLK serializes all flush requests
 * among CPUs.
 */
blk_status_t qblk_flush_req(struct request_queue *q,
						struct qblk *qblk, struct qblk_queue *pq,
						struct request *req)
{
	unsigned int nr_rb = qblk->nr_queues;
	struct qblk_persist_work *persist_work;

	WARN_ON(req->bio);
	//pr_notice("%s, rbindex=%u\n", __func__, pq->rb_idx);

	persist_work = qblk_persist_work_alloc_init(req, nr_rb);
	if (!persist_work)
		return BLK_STS_RESOURCE;

	while (nr_rb--)
		qblk_rb_persist_point_set(qblk, nr_rb, qblk_get_rb_by_cpuid(qblk, nr_rb),
												persist_work);

	qblk_write_force_kick_all(qblk);
	return BLK_STS_OK;
}

unsigned int qblk_rb_wrap_pos(struct qblk_rb *rb, unsigned int pos)
{
	return pos & rb->qblk->perrb_mask;
}

/*
 * Read available entries on rb and add them to the given bio. To avoid a memory
 * copy, a page reference to the write buffer is used to be added to the bio.
 *
 * This function is used by the write thread to form the write bio that will
 * persist data on the write buffer to the media.
 */
unsigned int qblk_rb_read_to_bio(struct qblk *qblk,
				struct qblk_rb *rb, struct nvm_rq *rqd,
				unsigned int pos, unsigned int nr_entries,
				unsigned int count)
{
	struct request_queue *q = qblk->dev->q;
	struct qblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	struct bio *bio = rqd->bio;
	struct qblk_rb_entry *entry;
	struct page *page;
	unsigned int pad = 0, to_read = nr_entries;
	unsigned int i;
	int flags;

	if (count < nr_entries) {
		pad = nr_entries - count;
		to_read = count;
	}

	c_ctx->sentry =	pos;
	c_ctx->nr_valid = to_read;
	c_ctx->nr_padded = pad;

	//pr_notice("%s,rb=%u,pos=%u,nr_entries=%u,count=%u\n", __func__,
	//	rb->rb_index,
	//	pos, nr_entries, count);

	for (i = 0; i < to_read; i++) {
		entry = qblk_rb_entry_by_index(qblk, rb, pos);

		/* A write has been allowed into the buffer, but data is still
		 * being copied to it. It is ok to busy wait.
		 */
retry:
		flags = READ_ONCE(entry->w_ctx.flags);

		if (!(flags & QBLK_WRITTEN_DATA)) {
			io_schedule();
			goto retry;
		}

		page = virt_to_page(entry->data);
		if (!page) {
			pr_err("qblk: could not allocate write bio page\n");
			flags &= ~QBLK_WRITTEN_DATA;
			flags |= QBLK_SUBMITTED_ENTRY;
			/* Release flags on context. Protect from writes */
			smp_store_release(&entry->w_ctx.flags, flags);
			return NVM_IO_ERR;
		}

		if (bio_add_pc_page(q, bio, page, rb->seg_size, 0) !=
								rb->seg_size) {
			pr_err("qblk: could not add page to write bio\n");
			flags &= ~QBLK_WRITTEN_DATA;
			flags |= QBLK_SUBMITTED_ENTRY;
			/* Release flags on context. Protect from writes */
			smp_store_release(&entry->w_ctx.flags, flags);
			return NVM_IO_ERR;
		}

		flags &= ~QBLK_WRITTEN_DATA;
		flags |= QBLK_SUBMITTED_ENTRY;

		/* Release flags on context. Protect from writes */
		smp_store_release(&entry->w_ctx.flags, flags);

		pos++;

	}

	if (pad) {
		if (qblk_bio_add_pages(qblk, bio, GFP_KERNEL, pad)) {
			pr_err("qblk: could not pad page in write bio\n");
			return NVM_IO_ERR;
		}
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(pad, &qblk->padded_writes);
#endif

	return NVM_IO_OK;
}

/*
 * Look at qblk_rb_may_write_user comment
 */
static int qblk_rb_may_write_gc(struct qblk *qblk,
			struct qblk_rb *rb, struct ch_info *chi,
			unsigned int nr_entries,
			unsigned int *pos)
{
	int ret;

	if (qblk_rl_gc_maynot_insert(&qblk->rl, nr_entries))
		return 1;

#ifdef QBLKe_DEBUG
	atomic_add(nr_entries, &qblk->rl.gc_accepted);
#endif
	spin_lock(&rb->w_lock);
	ret = qblk_rb_maynot_write(qblk, rb, nr_entries, pos);
	if (ret) {
		spin_unlock(&rb->w_lock);
		return ret;
	}

	qblk_rl_gc_in(&qblk->rl, nr_entries);
	spin_unlock(&rb->w_lock);

#ifdef QBLKe_DEBUG
	atomic_add(nr_entries, &qblk->rl.gc_queued);
#endif

	return 0;
}

/*
 * On GC the incoming lbas are not necessarily sequential. Also, some of the
 * lbas might not be valid entries, which are marked as empty by the GC thread
 */
int qblk_write_gc_to_cache(struct qblk *qblk, struct qblk_gc_rq *gc_rq)
{
	struct qblk_w_ctx w_ctx;
	unsigned int bpos;
	void *data = gc_rq->data;
	int i, valid_entries;
	int cpuid;
	struct qblk_rb *rb = NULL, *last_rb = NULL;
	struct ch_info *chi = gc_rq->chi;
	int ret;

#if 0
	struct ppa_addr ppa_gc;
	struct ppa_addr ppa_empty = {.ppa = ADDR_EMPTY};
#endif

#ifdef QBLKe_DEBUG
	atomic_add(1, &qblk->rl.gc_write_rq);
#endif
	for (i = 0, valid_entries = 0; i < gc_rq->nr_secs; i++) {
		if (gc_rq->lba_list[i] == ADDR_EMPTY)
			continue;

#ifdef QBLKe_DEBUG
		atomic_add(1, &qblk->rl.gc_prewrite);
#endif

retry:
		cpuid = get_cpu();
		rb = qblk_get_rb_by_cpuid(qblk, cpuid);
		ret = qblk_rb_may_write_gc(qblk, rb, chi, 1, &bpos);

		qblk_per_rb_account(qblk, cpuid, QBLK_GC_SUBMITTED, 1);

		if (ret) {
			put_cpu();
			//pr_notice("%s, rb %u ret %d\n", __func__, rb->rb_index, ret);
			//set_current_state(TASK_INTERRUPTIBLE);
			schedule();
			//usleep_range(128, 256);
			goto retry;
		}
		qblk_per_rb_account(qblk, cpuid, QBLK_GC_ACCEPTED, 1);

		w_ctx.flags = QBLK_IOTYPE_GC;
		qblk_ppa_set_empty(&w_ctx.ppa);
		w_ctx.lba = gc_rq->lba_list[i];

		/* Since we only write one entry here,
		 * we don't need to wrap the bpos.
		 */
		qblk_rb_write_entry_gc(qblk, rb, data,
						w_ctx, gc_rq->line,
						gc_rq->paddr_list[i], bpos);

		data += QBLK_EXPOSED_PAGE_SIZE;
		valid_entries++;

		put_cpu();
		if (rb != last_rb) {
			if (last_rb)
				qblk_write_should_kick(qblk, last_rb->rb_index, 0);
			last_rb = rb;
		}


	}

	WARN_ONCE(gc_rq->secs_to_gc != valid_entries,
					"qblk: inconsistent GC write\n");
					
#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(valid_entries, &qblk->inflight_writes);
	atomic_long_add(valid_entries, &qblk->recov_gc_writes);
#endif

	if (likely(last_rb))
		qblk_write_should_kick(qblk, last_rb->rb_index, 0);

	return NVM_IO_OK;
}

int qblk_allocate_mqrwb(struct qblk *qblk, unsigned int nr_entries, gfp_t flags)
{
	qblk->mqrwb = alloc_percpu_gfp(struct qblk_rb, flags);
	if (!qblk->mqrwb)
		return -ENOMEM;
	return 0;
}

void qblk_free_mqrwb(struct qblk *qblk)
{
	free_percpu(qblk->mqrwb);
}

