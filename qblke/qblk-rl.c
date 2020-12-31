#include "qblk.h"

#define QBLK_RL_RETRY_THRESHOLD (64)

int qblk_rl_high_thrs(struct qblk_per_chnl_rl *rl)
{
	return rl->high;
}

unsigned long qblk_rl_nr_free_blks(struct qblk_per_chnl_rl *rl)
{
	return atomic_read(&rl->free_blocks);
}


static void qblk_rl_kick_u_timer(struct qblk_rl *rl)
{
	mod_timer(&rl->u_timer, jiffies + msecs_to_jiffies(5000));
}

void qblk_rl_user_in(struct qblk_rl *rl, int nr_entries)
{
	atomic_add(nr_entries, &rl->rb_user_cnt);

	/* Release user I/O state. Protect from GC */
	smp_store_release(&rl->rb_user_active, 1);
	qblk_rl_kick_u_timer(rl);
}

void qblk_rl_gc_in(struct qblk_rl *rl, int nr_entries)
{
	atomic_add(nr_entries, &rl->rb_gc_cnt);
}


void qblk_rl_out(struct qblk *qblk,
					int nr_user, int nr_gc)
{
	//struct qblk_rl *rl = &qblk->rl;

	//atomic_sub(nr_user, &rl->rb_user_cnt);
	//atomic_sub(nr_gc, &rl->rb_gc_cnt);
	//if (nr_gc)
	//	qblk_gc_writer_wakeup_all(qblk);
}


int qblk_rl_gc_maynot_insert(struct qblk_rl *rl,
					int nr_entries)
{
	int rb_gc_cnt;
	int rb_user_active, rb_gc_max;
	int retry_count = 0;

#ifdef QBLKe_DEBUG
	atomic_add(nr_entries, &rl->gc_attempt);
#endif

retry:
	/* If there is no user I/O let GC take over space on the write buffer */
	rb_user_active = READ_ONCE(rl->rb_user_active);
	rb_gc_cnt = atomic_read(&rl->rb_gc_cnt);
	rb_gc_max = atomic_read(&rl->rb_gc_max);

	//pr_notice("%s, rb_gc_cnt[%d] rb_gc_max[%d] rb_user_active[%d]",
	//			__func__, rb_gc_cnt, rb_gc_max, rb_user_active);

	if (rb_user_active) {
		if (rb_gc_cnt <= rb_gc_max) {
			return 0;
		} else {
			int rb_user_cnt = atomic_read(&rl->rb_user_cnt);
			int rb_user_max = atomic_read(&rl->rb_user_max);
			int user_cnt_now;

			if (rb_user_cnt > rb_user_max) {
				user_cnt_now = atomic_cmpxchg(&rl->rb_user_cnt, rb_user_cnt, 0);
				if (user_cnt_now == rb_user_cnt) {
					atomic_set(&rl->rb_gc_cnt, 0);
					return 0;
				}
				if (retry_count++ > QBLK_RL_RETRY_THRESHOLD)
					return 1;
				goto retry;
			}
			return 1;
		}
	}
	return 0;
}


/* We can insert if we're under the global rb_user_max limit */
int qblk_rl_user_maynot_insert(struct qblk *qblk, int nr_entries)
{
	struct qblk_rl *rl = &qblk->rl;
	int rb_user_cnt, rb_user_max;
	int retry_count = 0;

#ifdef QBLKe_DEBUG
	atomic_add(nr_entries, &rl->usr_attempt);
#endif

retry:
	/* If gc is not running, we can't limit the rate of user */
	if (qblk_gc_is_stopped(qblk))
		return 0;
	rb_user_cnt = atomic_read(&rl->rb_user_cnt);
	rb_user_max = atomic_read(&rl->rb_user_max);
	if (rb_user_cnt > rb_user_max) {
		int rb_gc_cnt = atomic_read(&rl->rb_gc_cnt);
		int rb_gc_max = atomic_read(&rl->rb_gc_max);
		int user_cnt_now;

		if (rb_gc_cnt > rb_gc_max) {
			user_cnt_now = atomic_cmpxchg(&rl->rb_user_cnt, rb_user_cnt, 0);
			if (user_cnt_now == rb_user_cnt) {
				atomic_set(&rl->rb_gc_cnt, 0);
				return 0;
			}
			if (retry_count++ > QBLK_RL_RETRY_THRESHOLD)
				return 1;
			goto retry;
		}
		return 1;
	}

	return 0;
}

static unsigned long qblk_rl_nr_user_free_blks(struct qblk_per_chnl_rl *rl)
{
	return atomic_read(&rl->free_user_blocks);
}

/* This function should be processed atomically to avoid competition. */
static void qblk_rl_update_gc_state(struct qblk_per_chnl_rl *pch_rl)
{
	unsigned long freeblks;
	unsigned long flags;
	int old_chnl_state;

	spin_lock_irqsave(&pch_rl->update_gc_state_lock, flags);
	freeblks = qblk_rl_nr_user_free_blks(pch_rl);
	if (freeblks >= pch_rl->high) {
		old_chnl_state = pch_rl->chnl_state;
		if (old_chnl_state != QBLK_RL_HIGH) {
			pch_rl->chnl_state = QBLK_RL_HIGH;
			qblk_gc_should_stop(pch_rl);
		}
	}
	else if (freeblks > pch_rl->rsv_blocks) {
		pch_rl->chnl_state = QBLK_RL_MID;
		qblk_gc_should_start(pch_rl);
	} else {
		pch_rl->chnl_state = QBLK_RL_LOW;
		qblk_gc_should_start(pch_rl);
	}
	spin_unlock_irqrestore(&pch_rl->update_gc_state_lock, flags);
}

static void __qblk_rl_update_rates(struct qblk_per_chnl_rl *pch_rl,
				   unsigned long free_blocks)
{
	struct qblk *qblk = pch_rl->qblk;
	struct qblk_rl *qblk_rl = &qblk->rl;
	int max = qblk_rl->rb_budget;
	unsigned int old_user_max;
#if 1
	if (free_blocks >= pch_rl->high) {
		old_user_max = atomic_xchg(&pch_rl->pch_rb_user_max, max);
		if (old_user_max != max) {
			atomic_add(max - old_user_max, &qblk_rl->rb_user_max);
			atomic_sub(max - old_user_max, &qblk_rl->rb_gc_max);
			//pr_notice("%s, high chnl[%u], freeblocks[%lu] usr+ gc- [%u]\n",
			//						__func__,
			//						pch_rl->chnl,
			//						free_blocks,
			//						max - old_user_max);
		}
	} else if (free_blocks > pch_rl->rsv_blocks) {
  		int user_max = qblk_rl->rb_budget * (free_blocks - pch_rl->rsv_blocks) / (pch_rl->high - pch_rl->rsv_blocks);
/*
		int shift = pch_rl->high_pw - qblk_rl->rb_windows_pw;
		int user_windows = free_blocks >> shift;
		int user_max = user_windows << QBLK_MAX_REQ_ADDRS_PW;
*/

		//user_max = 128;
		

		old_user_max = atomic_xchg(&pch_rl->pch_rb_user_max, user_max);

		if (old_user_max > user_max) {
			atomic_sub(old_user_max - user_max, &qblk_rl->rb_user_max);
			atomic_add(old_user_max - user_max, &qblk_rl->rb_gc_max);
			//pr_notice("%s, mid chnl[%u], freeblocks[%lu] usr- gc+ [%u]\n",
			//						__func__,
			//						pch_rl->chnl,
			//						free_blocks,
			//						old_user_max - user_max);
		} else if (old_user_max < user_max) {
			atomic_add(user_max - old_user_max, &qblk_rl->rb_user_max);
			atomic_sub(user_max - old_user_max, &qblk_rl->rb_gc_max);
			//pr_notice("%s, mid chnl[%u], usr+ gc- [%u]\n", __func__,
			//						pch_rl->chnl, user_max - old_user_max);
		}
	} else {
		old_user_max = atomic_xchg(&pch_rl->pch_rb_user_max, 0);
		if (old_user_max != 0) {
			atomic_sub(old_user_max, &qblk_rl->rb_user_max);
			atomic_add(old_user_max, &qblk_rl->rb_gc_max);
			//pr_notice("%s, low chnl[%u], freeblocks[%lu] usr- gc+ [%u]\n",
			//						__func__,
			//						pch_rl->chnl,
			//						free_blocks,
			//						old_user_max);
		}
	}
#endif
	/* TODO: If we get here from the following call stack:
	 *	qblk_init()-->
	 *	qblk_line_get_first_data()-->
	 *	qblk_rl_free_lines_dec()-->
	 *	__qblk_rl_update_rates()
	 * qblk_gc_init() is not called yet and thus qblk->per_channel_gc may be NULL.
	 * Under this circumstance, calling qblk_gc_should_start/stop takes no effect.
	 */
	qblk_rl_update_gc_state(pch_rl);
}


void qblk_rl_update_rates(struct qblk_per_chnl_rl *rl)
{
	__qblk_rl_update_rates(rl, qblk_rl_nr_user_free_blks(rl));
}

void qblk_rl_free_lines_inc(struct qblk_per_chnl_rl *pch_rl, struct qblk_line *line)
{
	int blk_in_line = atomic_read(&line->blk_in_line);
	int free_blocks;
	unsigned long flags;

	atomic_add(blk_in_line, &pch_rl->free_blocks);
	free_blocks = atomic_add_return(blk_in_line, &pch_rl->free_user_blocks);

	/* FIXME: If we close a line without writing
	 * all its data sectors, this calculation may be wrong?
	 */
	spin_lock_irqsave(&pch_rl->remain_secs_lock, flags);
	pch_rl->remain_secs += line->data_secs_in_line;
	//pr_notice("%s, remain_secs=%u, data_secs_in_line=%u\n",
	//	__func__, rl->remain_secs, line->data_secs_in_line);
	spin_unlock_irqrestore(&pch_rl->remain_secs_lock, flags);

	__qblk_rl_update_rates(pch_rl, free_blocks);
}

void qblk_rl_free_lines_dec(struct qblk_per_chnl_rl *pch_rl, struct qblk_line *line,
			    bool used)
{
	int blk_in_line = atomic_read(&line->blk_in_line);
	int free_blocks;

	atomic_sub(blk_in_line, &pch_rl->free_blocks);

	if (used)
		free_blocks = atomic_sub_return(blk_in_line,
							&pch_rl->free_user_blocks);
	else
		free_blocks = atomic_read(&pch_rl->free_user_blocks);

	__qblk_rl_update_rates(pch_rl, free_blocks);
}

static void qblk_rl_u_timer(struct timer_list *t)
{
	struct qblk_rl *global_rl = from_timer(global_rl, t, u_timer);

	/* Release user I/O state. Protect from GC */
	smp_store_release(&global_rl->rb_user_active, 0);
}


void qblk_rl_free(struct qblk_rl *rl)
{
	del_timer(&rl->u_timer);
}

int qblk_rl_init(struct qblk_rl *global_rl, int nr_rb)
{
	struct qblk *qblk = container_of(global_rl, struct qblk, rl);
	int nr_chnls = qblk->nr_channels;
	int budget;

	budget = qblk->rl.rb_budget * nr_chnls;

	//pr_notice("%s: total_buf_entries=%u\n",
	//				__func__, budget);

	/* To start with, all buffer is available to user I/O writers */
	atomic_set(&global_rl->rb_user_max, budget);
	atomic_set(&global_rl->rb_user_cnt, 0);

	atomic_set(&global_rl->rb_gc_max, 0);
	atomic_set(&global_rl->rb_gc_cnt, 0);

#ifdef QBLKe_DEBUG
	atomic_set(&global_rl->usr_attempt, 0);
	atomic_set(&global_rl->gc_attempt, 0);
	atomic_set(&global_rl->usr_accepted, 0);
	atomic_set(&global_rl->gc_accepted, 0);
	atomic_set(&global_rl->usr_queued, 0);
	atomic_set(&global_rl->gc_queued, 0);
	atomic_set(&global_rl->gc_read, 0);
	atomic_set(&global_rl->gc_prewrite, 0);
	atomic_set(&global_rl->gc_read_rq, 0);
	atomic_set(&global_rl->gc_write_rq, 0);
	atomic_set(&global_rl->gc_create_rq, 0);
	atomic_set(&global_rl->gc_read_queued, 0);

#endif

	global_rl->rb_user_active = 0;

	timer_setup(&global_rl->u_timer, qblk_rl_u_timer, 0);

	return 0;
}

void qblk_per_chnl_rl_free(struct qblk_per_chnl_rl *rl)
{
}


/*
 * Calculate the per-channel rate limiter.
 */
void qblk_per_chnl_rl_init(struct qblk *qblk,
			struct ch_info *chi, struct qblk_per_chnl_rl *pch_rl,
			int nr_free_blks)
{
	struct nvm_geo *geo = &qblk->dev->geo;
	struct qblk_metainfo *meta = &qblk->metainfo;
	sector_t provisioned;
	unsigned op_blks;
	int sec_meta, blk_meta;

	pch_rl->qblk = qblk;
	pch_rl->chnl = chi->ch_index;

	provisioned = nr_free_blks;
	provisioned *= (100 - qblk->op);
	sector_div(provisioned, 100);

	op_blks = nr_free_blks - provisioned;
	qblk->rl.total_blocks += nr_free_blks;

	sec_meta = (meta->smeta_sec + meta->emeta_sec[0]) * chi->nr_free_lines;
	blk_meta = DIV_ROUND_UP(sec_meta, geo->sec_per_chk);

	pch_rl->rsv_blocks = meta->blk_per_chline * QBLK_GC_RSV_LINE;
	pch_rl->high = op_blks - blk_meta - meta->blk_per_chline;
	pch_rl->high_pw = get_count_order(pch_rl->high);

	atomic_set(&pch_rl->free_blocks, nr_free_blks);
	atomic_set(&pch_rl->free_user_blocks, nr_free_blks);
	atomic_set(&pch_rl->pch_rb_user_max, qblk->rl.rb_budget);
	atomic_set(&pch_rl->wheel, 0);

	qblk->capacity += (provisioned - blk_meta) * geo->sec_per_chk;
	qblk->rl.nr_secs += (provisioned - blk_meta) * geo->sec_per_chk;

#if 0
	if (chi->ch_index == 0)
		pr_notice("%s, nr_free_blks %d, provisioned %lu, qblk->rl.total_blocks %lu, rl->rsv_blocks %u, rl->high %u, rl->high_pw %u\n",
				__func__, nr_free_blks, provisioned, qblk->rl.total_blocks,
				pch_rl->rsv_blocks, pch_rl->high, pch_rl->high_pw);
#endif

	/*
	 * rl->remain_secs holds the number
	 * of budget of free data sectors in this chnl.
	 * Since we need to maintain a data line and a
	 * data_next line for each channel, we should avoid
	 * fullfilling every sector in this channel.
	 * Instead, when we can't find another free line
	 * for data_next, we stop filling data into this channel.
	 */
	/* FIXME:
	 * If there are lots of bad blocks,
	 * this calculation may be incorrect?
	 */
	pch_rl->remain_secs =
		nr_free_blks * geo->sec_per_chk
		- meta->sec_per_chline
		- (meta->smeta_sec + meta->emeta_sec[0])
			* (chi->nr_lines - 1);
	spin_lock_init(&pch_rl->remain_secs_lock);
	spin_lock_init(&pch_rl->update_gc_state_lock);

#if 0
	if (chi->ch_index == 0)
		pr_notice("%s, remain_secs=%u\n", __func__, pch_rl->remain_secs);//506416

	if (chi->ch_index == 0)
		pr_notice("%s, ch[%d] high=%d,rsv=%d\n",
					__func__, chi->ch_index,
					pch_rl->high,
					pch_rl->rsv_blocks);
#endif

}


/*
 * Find out whether this channel has enough budget
 * for the drainning request.
 * If so, reserve enough space and return 0;
 * Otherwise, return -ENOSPC
 *
 * This function may be called by difference threads.
 */
int qblk_channel_maynot_writeback(struct qblk *qblk,
					struct ch_info *chi,
					unsigned int nr_sec_required)
{
	struct qblk_per_chnl_rl *pch_rl = &chi->per_ch_rl;
	unsigned long flags;

	if (test_bit(chi->ch_index, qblk->gc_active)) {
		unsigned int wheel = atomic_inc_return(&pch_rl->wheel);
		unsigned int weight = bitmap_weight(qblk->gc_active, qblk->gc_active_size);

		//There is no need to be too accurate here, so avoid getting the qblk->gc_active_lock.

		if ((wheel % qblk->nr_channels) >= weight)
			return -EAGAIN;
	}
	spin_lock_irqsave(&pch_rl->remain_secs_lock, flags);
 	if (pch_rl->remain_secs >= nr_sec_required) {
 		pch_rl->remain_secs -= nr_sec_required;
		//pr_notice("%s, remain_secs=%u, nr_sec_required=%u\n",
		//		__func__, rl->remain_secs, nr_sec_required);
		spin_unlock_irqrestore(&pch_rl->remain_secs_lock, flags);
		return 0;
 	} else {
		spin_unlock_irqrestore(&pch_rl->remain_secs_lock, flags);
		return -ENOSPC;
 	}
}

