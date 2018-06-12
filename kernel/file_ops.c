#include <hfi1/file_ops.h>
#include <hfi1/hfi.h>
#include <hfi1/user_sdma.h>
#include <hfi1/sdma.h>
#include <hfi1/ihk_hfi1_common.h>
#include <hfi1/user_exp_rcv.h>
#include <errno.h>

//#define DEBUG_PRINT_FOPS

#ifdef DEBUG_PRINT_FOPS
#define	dkprintf(...) kprintf(__VA_ARGS__)
#define	ekprintf(...) kprintf(__VA_ARGS__)
#else
#define dkprintf(...) do { if (0) kprintf(__VA_ARGS__); } while (0)
#define	ekprintf(...) kprintf(__VA_ARGS__)
#endif

long hfi1_file_ioctl(void *private_data, unsigned int cmd,
			    unsigned long arg, unsigned long t_s)
{
	struct hfi1_filedata *fd = private_data;
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_tid_info tinfo;
	unsigned long addr;
	int ret = -ENOTSUPP;

	hfi1_cdbg(IOCTL, "IOCTL recv: 0x%x", cmd);
	if (cmd != HFI1_IOCTL_ASSIGN_CTXT &&
	    cmd != HFI1_IOCTL_GET_VERS &&
	    !uctxt)
		return -EINVAL;

	switch (cmd) {
	case HFI1_IOCTL_ASSIGN_CTXT:
#if 0	
		if (uctxt)
			return -EINVAL;

		if (copy_from_user(&uinfo,
				   (struct hfi1_user_info __user *)arg,
				   sizeof(uinfo)))
			return -EFAULT;

		ret = assign_ctxt(fp, &uinfo);
		if (ret < 0)
			return ret;
		ret = setup_ctxt(fp);
		if (ret)
			return ret;
		ret = user_init(fp);
#endif
		dkprintf("%s: HFI1_IOCTL_ASSIGN_CTXT \n", __FUNCTION__);
		break;
	case HFI1_IOCTL_CTXT_INFO:
#if 0
		ret = get_ctxt_info(fp, (void __user *)(unsigned long)arg,
				    sizeof(struct hfi1_ctxt_info));
#endif
		dkprintf("%s: HFI1_IOCTL_CTXT_INFO \n", __FUNCTION__);
		break;
	case HFI1_IOCTL_USER_INFO:
#if 0
		ret = get_base_info(fp, (void __user *)(unsigned long)arg,
				    sizeof(struct hfi1_base_info));
#endif
		dkprintf("%s: HFI1_IOCTL_USER_INFO \n", __FUNCTION__);
		break;
	case HFI1_IOCTL_CREDIT_UPD:
#if 0	
		if (uctxt)
			sc_return_credits(uctxt->sc);
#endif
		dkprintf("%s: HFI1_IOCTL_CREDIT_UPD \n", __FUNCTION__);
		break;

	case HFI1_IOCTL_TID_UPDATE:
		dkprintf("%s: HFI1_IOCTL_TID_UPDATE \n", __FUNCTION__);
		if (copy_from_user(&tinfo,
				   (struct hfi11_tid_info __user *)arg,
				   sizeof(tinfo)))
			return -EFAULT;

		ret = hfi1_user_exp_rcv_setup(fd, &tinfo);
		if (!ret) {
			/*
			 * Copy the number of tidlist entries we used
			 * and the length of the buffer we registered.
			 * These fields are adjacent in the structure so
			 * we can copy them at the same time.
			 */
			addr = arg + offsetof(struct hfi1_tid_info, tidcnt);
			if (copy_to_user((void __user *)addr, &tinfo.tidcnt,
					 sizeof(tinfo.tidcnt) +
					 sizeof(tinfo.length)))
				ret = -EFAULT;
		}
		break;

	case HFI1_IOCTL_TID_FREE:
		dkprintf("%s: HFI1_IOCTL_TID_FREE \n", __FUNCTION__);
		if (copy_from_user(&tinfo,
				   (struct hfi11_tid_info __user *)arg,
				   sizeof(tinfo)))
			return -EFAULT;

		ret = hfi1_user_exp_rcv_clear(fd, &tinfo);
		if (ret)
			break;
		addr = arg + offsetof(struct hfi1_tid_info, tidcnt);
		if (copy_to_user((void __user *)addr, &tinfo.tidcnt,
				 sizeof(tinfo.tidcnt)))
			ret = -EFAULT;
		break;

	case HFI1_IOCTL_TID_INVAL_READ:
		dkprintf("%s: HFI1_IOCTL_TID_INVAL_READ \n", __FUNCTION__);
		if (copy_from_user(&tinfo,
				   (struct hfi11_tid_info __user *)arg,
				   sizeof(tinfo)))
			return -EFAULT;

		ret = hfi1_user_exp_rcv_invalid(fd, &tinfo);
		if (ret)
			break;
		addr = arg + offsetof(struct hfi1_tid_info, tidcnt);
		if (copy_to_user((void __user *)addr, &tinfo.tidcnt,
				 sizeof(tinfo.tidcnt)))
			ret = -EFAULT;
		break;

	case HFI1_IOCTL_RECV_CTRL:
#if 0
		ret = get_user(uval, (int __user *)arg);
		if (ret != 0)
			return -EFAULT;
		ret = manage_rcvq(uctxt, fd->subctxt, uval);
#endif
		dkprintf("%s: HFI1_IOCTL_RECV_CTRL \n", __FUNCTION__);
		break;

	case HFI1_IOCTL_POLL_TYPE:
#if 0
		ret = get_user(uval, (int __user *)arg);
		if (ret != 0)
			return -EFAULT;
		uctxt->poll_type = (typeof(uctxt->poll_type))uval;
#endif
		dkprintf("%s: HFI1_IOCTL_POLL_TYPE \n", __FUNCTION__);
		break;

	case HFI1_IOCTL_ACK_EVENT:
#if 0
		ret = get_user(ul_uval, (unsigned long __user *)arg);
		if (ret != 0)
			return -EFAULT;
		ret = user_event_ack(uctxt, fd->subctxt, ul_uval);
#endif
		dkprintf("%s: HFI1_IOCTL_ACK_EVENT \n", __FUNCTION__);
		break;

	case HFI1_IOCTL_SET_PKEY:
#if 0
		ret = get_user(uval16, (u16 __user *)arg);
		if (ret != 0)
			return -EFAULT;
		if (HFI1_CAP_IS_USET(PKEY_CHECK))
			ret = set_ctxt_pkey(uctxt, fd->subctxt, uval16);
		else
			return -EPERM;
#endif
		ret = -ENODEV;
		dkprintf("%s: HFI1_IOCTL_SET_PKEY \n", __FUNCTION__);
		break;

	case HFI1_IOCTL_CTXT_RESET: {
#if 0
		struct send_context *sc;
		struct hfi1_devdata *dd;

		if (!uctxt || !uctxt->dd || !uctxt->sc)
			return -EINVAL;

		/*
		 * There is no protection here. User level has to
		 * guarantee that no one will be writing to the send
		 * context while it is being re-initialized.
		 * If user level breaks that guarantee, it will break
		 * it's own context and no one else's.
		 */
		dd = uctxt->dd;
		sc = uctxt->sc;
		/*
		 * Wait until the interrupt handler has marked the
		 * context as halted or frozen. Report error if we time
		 * out.
		 */
		wait_event_interruptible_timeout(
			sc->halt_wait, (sc->flags & SCF_HALTED),
			msecs_to_jiffies(SEND_CTXT_HALT_TIMEOUT));
		if (!(sc->flags & SCF_HALTED))
			return -ENOLCK;

		/*
		 * If the send context was halted due to a Freeze,
		 * wait until the device has been "unfrozen" before
		 * resetting the context.
		 */
		if (sc->flags & SCF_FROZEN) {
			wait_event_interruptible_timeout(
				dd->event_queue,
				!(ACCESS_ONCE(dd->flags) & HFI1_FROZEN),
				msecs_to_jiffies(SEND_CTXT_HALT_TIMEOUT));
			if (dd->flags & HFI1_FROZEN)
				return -ENOLCK;

			if (dd->flags & HFI1_FORCED_FREEZE)
				/*
				 * Don't allow context reset if we are into
				 * forced freeze
				 */
				return -ENODEV;

			sc_disable(sc);
			ret = sc_enable(sc);
			hfi1_rcvctrl(dd, HFI1_RCVCTRL_CTXT_ENB,
				     uctxt->ctxt);
		} else {
			ret = sc_restart(sc);
		}
		if (!ret)
			sc_return_credits(sc);
		break;
#endif
		dkprintf("%s: HFI1_IOCTL_CTXT_RESET \n", __FUNCTION__);
		break;
	}

	case HFI1_IOCTL_GET_VERS:
#if 0
		uval = HFI1_USER_SWVERSION;
		if (put_user(uval, (int __user *)arg))
			return -EFAULT;
#endif
		dkprintf("%s: HFI1_IOCTL_GET_VERS \n", __FUNCTION__);
		break;

	default:
		return -ENOTSUPP;
	}
	return ret;
}

ssize_t hfi1_aio_write(void *private_data, const struct iovec *iovec, unsigned long dim)
{
	struct hfi1_filedata *fd = private_data;
	struct hfi1_user_sdma_pkt_q *pq = fd->pq;
	struct hfi1_user_sdma_comp_q *cq = fd->cq;
	int done = 0, reqs = 0;

	if (!cq || !pq)
		return -EIO;

	if (!dim)
		return -EINVAL;

	hfi1_cdbg(SDMA, "SDMA request from %u:%u (%lu)",
		fd->uctxt->ctxt, fd->subctxt, dim);

	if (atomic_read(&pq->n_reqs) == pq->n_max_reqs)
		return -ENOSPC;

	while (dim) {
		int ret;
		unsigned long count = 0;

		ret = hfi1_user_sdma_process_request(
			private_data, (struct iovec *)(iovec + done),
			dim, &count);
		if (ret) {
			reqs = ret;
			break;
		}
		dim -= count;
		done += count;
		reqs++;
	}

	return reqs;
}

