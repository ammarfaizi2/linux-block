#include <linux/uaccess.h>
#include <linux/export.h>
#include <linux/filter.h>
#include <linux/compat.h>

static struct bpf_prog *get_filter(struct sock_fprog *uprog)
{
	struct sock_fprog_kern fprog;
	struct bpf_prog *res = NULL;
	int err;

	if (!uprog->len)
		return NULL;

	/* uprog->len is unsigned short, so no overflow here */
	fprog.len = uprog->len * sizeof(struct sock_filter);
	fprog.filter = memdup_user(uprog->filter, fprog.len);
	if (IS_ERR(fprog.filter))
		return ERR_CAST(fprog.filter);

	err = bpf_prog_create(&res, &fprog);
	kfree(fprog.filter);

	return err ? ERR_PTR(err) : res;
}

struct bpf_prog *ppp_get_filter(struct sock_fprog __user *p)
{
	struct sock_fprog uprog;

	if (copy_from_user(&uprog, p, sizeof(struct sock_fprog)))
		return ERR_PTR(-EFAULT);
	return get_filter(&uprog);
}
EXPORT_SYMBOL(ppp_get_filter);

#ifdef CONFIG_COMPAT
struct bpf_prog *compat_ppp_get_filter(struct sock_fprog32 __user *p)
{
	struct sock_fprog32 uprog32;
	struct sock_fprog uprog;

	if (copy_from_user(&uprog32, p, sizeof(struct sock_fprog32)))
		return ERR_PTR(-EFAULT);
	uprog.len = uprog32.len;
	uprog.filter = compat_ptr(uprog32.filter);
	return get_filter(&uprog);
}
EXPORT_SYMBOL(compat_ppp_get_filter);
#endif
