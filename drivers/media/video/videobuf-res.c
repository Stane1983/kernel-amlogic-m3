/*******************************************************************
 *
 *  Copyright C 2012 by Amlogic, Inc. All Rights Reserved.
 *
 *  Description:
 *
 *  Author: Amlogic Software
 *  Created: 2012/9/6   16:46
 *
 *******************************************************************/


#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <media/videobuf-res.h>
#include <linux/io.h>

struct videobuf_res_memory {
	u32 magic;
	void *vaddr;
	resource_size_t phy_addr;
	unsigned long size;
};

static int debug;
module_param(debug, int, 0644);

#define MAGIC_RE_MEM 0x123039dc
#define MAGIC_CHECK(is, should)						    \
	if (unlikely((is) != (should)))	{				    \
		printk(KERN_ERR "magic mismatch: %x expected %x\n", (is), (should)); \
		BUG();							    \
	}

#define dprintk(level, fmt, arg...)					\
	if (debug >= level)						\
		printk(KERN_DEBUG "vbuf-resource: " fmt , ## arg)

static void* res_alloc(struct videobuf_queue *q,size_t boff,unsigned long size, resource_size_t* phy_addr)
{
	void __iomem *ret = NULL; 
	struct videobuf_res_privdata *res = NULL;
	long res_size = 0;

	BUG_ON(!size);

	BUG_ON(!q->priv_data);

	res  = (struct videobuf_res_privdata *)q->priv_data;
	MAGIC_CHECK(res->magic, MAGIC_RE_MEM);

	res_size = res->end-res->start+1;
	if(boff+size<=res_size){
		*phy_addr = res->start+boff;
		//ret = ioremap_wc(*phy_addr,size);
		//if(!ret)
		//	*phy_addr = 0;
	}else{
		printk(KERN_ERR "videobuf_res alloc buff is too small: %lx expected %lx\n", res_size, boff+size);
	}
	return (void*)ret;
}

static void res_free(struct videobuf_res_memory *mem)
{
	if(mem->vaddr)
		iounmap((void __iomem *)mem->vaddr);
	mem->vaddr = NULL;
	mem->size = 0;
	mem->phy_addr = 0;
	return;
}

static void
videobuf_vm_open(struct vm_area_struct *vma)
{
	struct videobuf_mapping *map = vma->vm_private_data;

	dprintk(2,"vm_open %p [count=%u,vma=%08lx-%08lx]\n",
		map, map->count, vma->vm_start, vma->vm_end);

	map->count++;
}

static void videobuf_vm_close(struct vm_area_struct *vma)
{
	struct videobuf_mapping *map = vma->vm_private_data;
	struct videobuf_queue *q = map->q;
	int i;

	dprintk(2,"vm_close %p [count=%u,vma=%08lx-%08lx]\n",
		map, map->count, vma->vm_start, vma->vm_end);

	map->count--;
	if (0 == map->count) {
		struct videobuf_res_memory *mem;

		dprintk(1,"munmap %p q=%p\n", map, q);
		//videobuf_queue_lock(q);
		mutex_lock(&q->vb_lock);
		/* We need first to cancel streams, before unmapping */
		if (q->streaming)
			videobuf_queue_cancel(q);

		for (i = 0; i < VIDEO_MAX_FRAME; i++) {
			if (NULL == q->bufs[i])
				continue;

			if (q->bufs[i]->map != map)
				continue;

			mem = q->bufs[i]->priv;
			if (mem) {
				/* This callback is called only if kernel has
				   allocated memory and this memory is mmapped.
				   In this case, memory should be freed,
				   in order to do memory unmap.
				 */

				MAGIC_CHECK(mem->magic, MAGIC_RE_MEM);

				dprintk(1,"buf[%d] freeing %p\n",
					i, mem->vaddr);

				res_free(mem);
			}

			q->bufs[i]->map   = NULL;
			q->bufs[i]->baddr = 0;
		}

		kfree(map);
		mutex_unlock(&q->vb_lock);
		//videobuf_queue_unlock(q);
	}
}

static const struct vm_operations_struct videobuf_vm_ops = {
	.open     = videobuf_vm_open,
	.close    = videobuf_vm_close,
};

static void *__videobuf_alloc(size_t size)
{
	struct videobuf_res_memory *mem;
	struct videobuf_buffer *vb;

	vb = kzalloc(size + sizeof(*mem), GFP_KERNEL);
	if (vb) {
		mem = vb->priv = ((char *)vb) + size;
		mem->magic = MAGIC_RE_MEM;

		dprintk(1, "%s: allocated at %p(%ld+%ld) & %p(%ld)\n",
			__func__, vb, (long)sizeof(*vb), (long)size - sizeof(*vb),
			mem, (long)sizeof(*mem));
	}

	return vb;
}

static void *__videobuf_to_vaddr(struct videobuf_buffer *buf)
{
	struct videobuf_res_memory *mem = buf->priv;

	BUG_ON(!mem);
	MAGIC_CHECK(mem->magic, MAGIC_RE_MEM);

	return mem->vaddr;
}

static int __videobuf_iolock(struct videobuf_queue *q,
			     struct videobuf_buffer *vb,
			     struct v4l2_framebuffer *fbuf)
{
	struct videobuf_res_memory *mem = vb->priv;

	BUG_ON(!mem);
	MAGIC_CHECK(mem->magic, MAGIC_RE_MEM);

	switch (vb->memory) {
	case V4L2_MEMORY_MMAP:
		dprintk(1,"%s memory method MMAP\n", __func__);

		/* All handling should be done by __videobuf_mmap_mapper() */
		if (!mem->phy_addr) {
			printk(KERN_ERR "%s memory is not alloced/mmapped.\n",__func__);
			return -EINVAL;
		}
		break;
	case V4L2_MEMORY_USERPTR:
		dprintk(1,"%s memory method USERPTR\n", __func__);
		return -EINVAL;
	case V4L2_MEMORY_OVERLAY:
	default:
		dprintk(1,"%s memory method OVERLAY/unknown\n",
			__func__);
		return -EINVAL;
	}

	return 0;
}

static int __videobuf_sync(struct videobuf_queue *q,
               struct videobuf_buffer *buf)
{
    return 0;
}

static int __videobuf_mmap_free(struct videobuf_queue *q)
{
    unsigned int i;

    dprintk(1, "%s\n", __func__);
    for (i = 0; i < VIDEO_MAX_FRAME; i++) {
        if (q->bufs[i]) {
            if (q->bufs[i]->map)
                return -EBUSY;
        }
    }

    return 0;
}

static int __videobuf_mmap_mapper(struct videobuf_queue *q,
				  struct vm_area_struct *vma)
{
	struct videobuf_res_memory *mem;
	struct videobuf_mapping *map;
	unsigned int first;
	int retval;
	unsigned long size;
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	dprintk(2,"%s\n", __func__);
    if (!(vma->vm_flags & VM_WRITE) || !(vma->vm_flags & VM_SHARED))
        return -EINVAL;
    /* look for first buffer to map */
    for (first = 0; first < VIDEO_MAX_FRAME; first++) {
        if (NULL == q->bufs[first])
            continue;

        if (V4L2_MEMORY_MMAP != q->bufs[first]->memory)
            continue;
        if (q->bufs[first]->boff == offset)
            break;
    }
    if (VIDEO_MAX_FRAME == first) {
        dprintk(1,"mmap app bug: offset invalid [offset=0x%lx]\n",
            (vma->vm_pgoff << PAGE_SHIFT));
        return -EINVAL;
    }
	/* create mapping + update buffer list */
	map = kzalloc(sizeof(struct videobuf_mapping), GFP_KERNEL);
	if (NULL == map)
		return -ENOMEM;
    q->bufs[first]->map = map;
    map->start = vma->vm_start;
    map->end   = vma->vm_end;
    map->q     = q;

    q->bufs[first]->baddr = vma->vm_start;

    mem = q->bufs[first]->priv;
	BUG_ON(!mem);
	MAGIC_CHECK(mem->magic, MAGIC_RE_MEM);
	mem->size = PAGE_ALIGN(vma->vm_end - vma->vm_start);
	mem->vaddr = res_alloc(q, offset, mem->size, &mem->phy_addr);
	//if ((!mem->vaddr)||(!mem->phy_addr)){
	if (!mem->phy_addr){
		printk(KERN_ERR  "res_alloc size %ld failed\n",
			mem->size);
		goto error;
	}
	dprintk(1,"res_alloc data is at addr 0x%x (size %ld)\n",
		mem->phy_addr, mem->size);

	/* Try to remap memory */

	size = vma->vm_end - vma->vm_start;
	size = (size < mem->size) ? size : mem->size;

	//vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	retval = remap_pfn_range(vma, vma->vm_start,
				 mem->phy_addr >> PAGE_SHIFT,
				 size, vma->vm_page_prot);
	if (retval) {
		printk(KERN_ERR "mmap: remap failed with error %d. ", retval);
		res_free(mem);
		goto error;
	}
	vma->vm_ops          = &videobuf_vm_ops;
	vma->vm_flags       |= (VM_DONTEXPAND| VM_IO | VM_RESERVED);
	vma->vm_private_data = map;

    dprintk(1,"mmap %p: q=%p %08lx-%08lx (%lx) pgoff %08lx buf %d\n",
        map, q, vma->vm_start, vma->vm_end,
        (long int) q->bufs[first]->bsize,
        vma->vm_pgoff, first);

	videobuf_vm_open(vma);
	return 0;

error:
	kfree(map);
	return -ENOMEM;
}

static int __videobuf_copy_to_user ( struct videobuf_queue *q,
                char __user *data, size_t count,
                int nonblocking )
{
    struct videobuf_res_memory *mem=q->read_buf->priv;
    BUG_ON (!mem);
    MAGIC_CHECK(mem->magic,MAGIC_RE_MEM);

    BUG_ON (!mem->vaddr);

    /* copy to userspace */
    if (count > q->read_buf->size - q->read_off)
        count = q->read_buf->size - q->read_off;

    if (copy_to_user(data, mem->vaddr+q->read_off, count))
        return -EFAULT;

    return count;
}


static int __videobuf_copy_stream ( struct videobuf_queue *q,
                char __user *data, size_t count, size_t pos,
                int vbihack, int nonblocking )
{
    unsigned int  *fc;
    struct videobuf_res_memory *mem=q->read_buf->priv;
    BUG_ON (!mem);
    MAGIC_CHECK(mem->magic,MAGIC_RE_MEM);

    if (vbihack) {
        /* dirty, undocumented hack -- pass the frame counter
            * within the last four bytes of each vbi data block.
            * We need that one to maintain backward compatibility
            * to all vbi decoding software out there ... */
        fc  = (unsigned int*)mem->vaddr;
        fc += (q->read_buf->size>>2) -1;
        *fc = q->read_buf->field_count >> 1;
        dprintk(1,"vbihack: %d\n",*fc);
    }

    /* copy stuff using the common method */
    count = __videobuf_copy_to_user (q,data,count,nonblocking);

    if ( (count==-EFAULT) && (0 == pos) )
        return -EFAULT;

    return count;
}

static struct videobuf_qtype_ops qops = {
	.magic        = MAGIC_QTYPE_OPS,

	.alloc        = __videobuf_alloc,
	.iolock       = __videobuf_iolock,
	.sync         = __videobuf_sync,
	.mmap_free    = __videobuf_mmap_free,
	.mmap_mapper  = __videobuf_mmap_mapper,
    .video_copy_to_user = __videobuf_copy_to_user,
    .copy_stream  = __videobuf_copy_stream,
	.vmalloc      = __videobuf_to_vaddr,
};

void videobuf_queue_res_init(struct videobuf_queue *q,
				    const struct videobuf_queue_ops *ops,
				    struct device *dev,
				    spinlock_t *irqlock,
				    enum v4l2_buf_type type,
				    enum v4l2_field field,
				    unsigned int msize,
				    void *priv)
{
	struct videobuf_res_privdata* res = (struct videobuf_res_privdata*)priv;
	
	BUG_ON(!res);
	MAGIC_CHECK(res->magic, MAGIC_RE_MEM);

	if(res->start>=res->end){
		printk(KERN_ERR "videobuf_queue_res_init: resource is invalid.\n");
		return;
	}	
	videobuf_queue_core_init(q, ops, dev, irqlock, type, field, msize,
	 	priv, &qops);
	return;
}
EXPORT_SYMBOL_GPL(videobuf_queue_res_init);

resource_size_t videobuf_to_res(struct videobuf_buffer *buf)
{
	struct videobuf_res_memory *mem = buf->priv;

	BUG_ON(!mem);
	MAGIC_CHECK(mem->magic, MAGIC_RE_MEM);

	return mem->phy_addr;
}
EXPORT_SYMBOL_GPL(videobuf_to_res);

void videobuf_res_free(struct videobuf_queue *q,
			      struct videobuf_buffer *buf)
{
	struct videobuf_res_memory *mem = buf->priv;

	/* mmapped memory can't be freed here, otherwise mmapped region
	   would be released, while still needed. In this case, the memory
	   release should happen inside videobuf_vm_close().
	   So, it should free memory only if the memory were allocated for
	   read() operation.
	 */
	if (buf->memory != V4L2_MEMORY_USERPTR)
		return;

	if (!mem)
		return;

	MAGIC_CHECK(mem->magic, MAGIC_RE_MEM);

	/* handle user space pointer case */
	if (buf->baddr) {
		return;
	}

	/* read() method */
	res_free(mem);
	return;
}
EXPORT_SYMBOL_GPL(videobuf_res_free);

MODULE_DESCRIPTION("helper module to manage video4linux resource buffers");
MODULE_AUTHOR("Amlogic");
MODULE_LICENSE("GPL");
