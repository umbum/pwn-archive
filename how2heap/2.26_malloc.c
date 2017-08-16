static void *
_int_malloc (mstate av, size_t bytes)
{
    INTERNAL_SIZE_T nb;               /* normalized request size */
    unsigned int idx;                 /* associated bin index */
    mbinptr bin;                      /* associated bin */

    mchunkptr victim;                 /* inspected/selected chunk */
    INTERNAL_SIZE_T size;             /* its size */
    int victim_index;                 /* its bin index */

    mchunkptr remainder;              /* remainder from a split */
    unsigned long remainder_size;     /* its size */

    unsigned int block;               /* bit map traverser */
    unsigned int bit;                 /* bit map traverser */
    unsigned int map;                 /* current word of binmap */

    mchunkptr fwd;                    /* misc temp for linking */
    mchunkptr bck;                    /* misc temp for linking */

#if USE_TCACHE
    size_t tcache_unsorted_count;	    /* count of unsorted chunks processed */
#endif

    const char *errstr = NULL;

    /*
       Convert request size to internal form by adding SIZE_SZ bytes
       overhead plus possibly more to obtain necessary alignment and/or
       to obtain a size of at least MINSIZE, the smallest allocatable
       size. Also, checked_request2size traps (returning 0) request sizes
       that are so large that they wrap around zero when padded and
       aligned.
     */

    checked_request2size (bytes, nb);

    /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
       mmap.  */
    if (__glibc_unlikely (av == NULL))
    {
        void *p = sysmalloc (nb, av);
        if (p != NULL)
            alloc_perturb (p, bytes);
        return p;
    }

    /*
       If the size qualifies as a fastbin, first check corresponding bin.
       This code is safe to execute even if av is not yet initialized, so we
       can try it without checking, which saves some time on this fast path.
     */

#define REMOVE_FB(fb, victim, pp)   \
  do						    	\
    {						    	\
      victim = pp;			    	\
      if (victim == NULL)	    	\
	break;					    	\
    }						    	\
  while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim)) \
	 != victim);			    	\

    if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
        idx = fastbin_index (nb);
        mfastbinptr *fb = &fastbin (av, idx);
        mchunkptr pp = *fb;
        REMOVE_FB (fb, victim, pp);
        if (victim != 0)
        {
            /***** fastbins size check *****/
            if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
            {
                errstr = "malloc(): memory corruption (fast)";
errout:
                malloc_printerr (check_action, errstr, chunk2mem (victim), av);
                return NULL;
            }
            check_remalloced_chunk (av, victim, nb);
#if USE_TCACHE
            /* While we're here, if we see other chunks of the same size,
               stash them in the tcache.  */
            size_t tc_idx = csize2tidx (nb);
            if (tcache && tc_idx < mp_.tcache_bins)
            {
                mchunkptr tc_victim;

                /* While bin not empty and tcache not full, copy chunks over.  */
                while (tcache->counts[tc_idx] < mp_.tcache_count
                        && (pp = *fb) != NULL)
                {
                    REMOVE_FB (fb, tc_victim, pp);
                    if (tc_victim != 0)
                    {
                        tcache_put (tc_victim, tc_idx);
                    }
                }
            }
#endif
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
        }
    }

    /*
       If a small request, check regular bin.  Since these "smallbins"
       hold one size each, no searching within bins is necessary.
       (For a large request, we need to wait until unsorted chunks are
       processed to find best fit. But for small ones, fits are exact
       anyway, so we can check now, which is faster.)
     */
// FIFO니까, unsorted bin's chunk 보다 smallbins's chunk를 먼저 꺼낸다.
    if (in_smallbin_range (nb))
    {
        idx = smallbin_index (nb);
        bin = bin_at (av, idx);

        if ((victim = last (bin)) != bin)
        {
            if (victim == 0) /* initialization check */
                malloc_consolidate (av);
            /***** smallbins bk check & unlink *****/
            else
            {
                bck = victim->bk;
                if (__glibc_unlikely (bck->fd != victim))
                {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                set_inuse_bit_at_offset (victim, nb);
                bin->bk = bck;
                bck->fd = bin;

                if (av != &main_arena)
                    set_non_main_arena (victim);
                check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
                /* While we're here, if we see other chunks of the same size,
                   stash them in the tcache.  */
                size_t tc_idx = csize2tidx (nb);
                if (tcache && tc_idx < mp_.tcache_bins)
                {
                    mchunkptr tc_victim;

                    /* While bin not empty and tcache not full, copy chunks over.  */
                    while (tcache->counts[tc_idx] < mp_.tcache_count
                            && (tc_victim = last (bin)) != bin)
                    {
                        if (tc_victim != 0)
                        {
                            bck = tc_victim->bk;
                            set_inuse_bit_at_offset (tc_victim, nb);
                            if (av != &main_arena)
                                set_non_main_arena (tc_victim);
                            bin->bk = bck;
                            bck->fd = bin;

                            tcache_put (tc_victim, tc_idx);
                        }
                    }
                }
#endif
                void *p = chunk2mem (victim);
                alloc_perturb (p, bytes);
                return p;
            }
        }
    }

    /*
       If this is a large request, consolidate fastbins before continuing.
       While it might look excessive to kill all fastbins before
       even seeing if there is space available, this avoids
       fragmentation problems normally associated with fastbins.
       Also, in practice, programs tend to have runs of either small or
       large requests, but less often mixtures, so consolidation is not
       invoked all that often in most programs. And the programs that
       it is called frequently in otherwise tend to fragment.
     */

    else
    {
        idx = largebin_index (nb);
        if (have_fastchunks (av))
            malloc_consolidate (av);
    }

    /*
       Process recently freed or remaindered chunks, taking one only if
       it is exact fit, or, if this a small request, the chunk is remainder from
       the most recent non-exact fit.  Place other traversed chunks in
       bins.  Note that this step is the only place in any routine where
       chunks are placed in bins.

       The outer loop here is needed because we might not realize until
       near the end of malloc that we should have consolidated, so must
       do so and retry. This happens at most once, and only when we would
       otherwise need to expand memory to service a "small" request.
     */

#if USE_TCACHE
    INTERNAL_SIZE_T tcache_nb = 0;
    size_t tc_idx = csize2tidx (nb);
    if (tcache && tc_idx < mp_.tcache_bins)
        tcache_nb = nb;
    int return_cached = 0;

    tcache_unsorted_count = 0;
#endif

    for (;; )
    {
        int iters = 0;
        while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
            /***** unsorted bin size check *****/
            bck = victim->bk;    // don't miss this
            if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)
                    || __builtin_expect (chunksize_nomask (victim) > av->system_mem, 0))
                malloc_printerr (check_action, "malloc(): memory corruption",
                                 chunk2mem (victim), av);
            size = chunksize (victim);

            /*
               If a small request, try to use last remainder if it is the
               only chunk in unsorted bin.  This helps promote locality for
               runs of consecutive small requests. This is the only
               exception to best-fit, and applies only when there is
               no exact fit for a small chunk.
             */

            if (in_smallbin_range (nb) &&
                    bck == unsorted_chunks (av) &&
                    victim == av->last_remainder &&
                    (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
                /* split and reattach remainder */
                remainder_size = size - nb;
                remainder = chunk_at_offset (victim, nb);
                unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
                av->last_remainder = remainder;
                remainder->bk = remainder->fd = unsorted_chunks (av);
                if (!in_smallbin_range (remainder_size))
                {
                    remainder->fd_nextsize = NULL;
                    remainder->bk_nextsize = NULL;
                }

                set_head (victim, nb | PREV_INUSE |
                          (av != &main_arena ? NON_MAIN_ARENA : 0));
                set_head (remainder, remainder_size | PREV_INUSE);
                set_foot (remainder, remainder_size);

                check_malloced_chunk (av, victim, nb);
                void *p = chunk2mem (victim);
                alloc_perturb (p, bytes);
                return p;
            }
            
            /***** unsorted bin unlink *****/
            // bck = victim -> bk;
            /* remove from unsorted list */
            unsorted_chunks (av)->bk = bck;
            bck->fd = unsorted_chunks (av);

            /* Take now instead of binning if exact fit */

            if (size == nb)
            {
                set_inuse_bit_at_offset (victim, size);
                if (av != &main_arena)
                    set_non_main_arena (victim);
#if USE_TCACHE
                /* Fill cache first, return to user only if cache fills.
                We may return one of these chunks later.  */
                if (tcache_nb
                        && tcache->counts[tc_idx] < mp_.tcache_count)
                {
                    tcache_put (victim, tc_idx);
                    return_cached = 1;
                    continue;
                }
                else
                {
#endif
                    check_malloced_chunk (av, victim, nb);
                    void *p = chunk2mem (victim);
                    alloc_perturb (p, bytes);
                    return p;
#if USE_TCACHE
                }
#endif
            }

            /* place chunk in bin */

            if (in_smallbin_range (size))
            {
                victim_index = smallbin_index (size);
                bck = bin_at (av, victim_index);
                fwd = bck->fd;
            }
            else
            {
                victim_index = largebin_index (size);
                bck = bin_at (av, victim_index);
                fwd = bck->fd;

                /* maintain large bins in sorted order */
                if (fwd != bck)
                {
                    /* Or with inuse bit to speed comparisons */
                    size |= PREV_INUSE;
                    /* if smaller than smallest, bypass loop below */
                    assert (chunk_main_arena (bck->bk));
                    if ((unsigned long) (size)
                            < (unsigned long) chunksize_nomask (bck->bk))
                    {
                        fwd = bck;
                        bck = bck->bk;

                        victim->fd_nextsize = fwd->fd;
                        victim->bk_nextsize = fwd->fd->bk_nextsize;
                        fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                    else
                    {
                        assert (chunk_main_arena (fwd));
                        while ((unsigned long) size < chunksize_nomask (fwd))
                        {
                            fwd = fwd->fd_nextsize;
                            assert (chunk_main_arena (fwd));
                        }

                        if ((unsigned long) size
                                == (unsigned long) chunksize_nomask (fwd))
                            /* Always insert in the second position.  */
                            fwd = fwd->fd;
                        else
                        {
                            victim->fd_nextsize = fwd;
                            victim->bk_nextsize = fwd->bk_nextsize;
                            fwd->bk_nextsize = victim;
                            victim->bk_nextsize->fd_nextsize = victim;
                        }
                        bck = fwd->bk;
                    }
                }
                else
                    victim->fd_nextsize = victim->bk_nextsize = victim;
            }

            mark_bin (av, victim_index);
            victim->bk = bck;
            victim->fd = fwd;
            fwd->bk = victim;
            bck->fd = victim;

#if USE_TCACHE
            /* If we've processed as many chunks as we're allowed while
            filling the cache, return one of the cached ones.  */
            ++tcache_unsorted_count;
            if (return_cached
                    && mp_.tcache_unsorted_limit > 0
                    && tcache_unsorted_count > mp_.tcache_unsorted_limit)
            {
                return tcache_get (tc_idx);
            }
#endif

#define MAX_ITERS       10000
            if (++iters >= MAX_ITERS)
                break;
        }

#if USE_TCACHE
        /* If all the small chunks we found ended up cached, return one now.  */
        if (return_cached)
        {
            return tcache_get (tc_idx);
        }
#endif

        /*
           If a large request, scan through the chunks of current bin in
           sorted order to find smallest that fits.  Use the skip list for this.
         */

        if (!in_smallbin_range (nb))
        {
            bin = bin_at (av, idx);

            /* skip scan if empty or largest chunk is too small */
            if ((victim = first (bin)) != bin
                    && (unsigned long) chunksize_nomask (victim)
                    >= (unsigned long) (nb))
            {
                victim = victim->bk_nextsize;
                while (((unsigned long) (size = chunksize (victim)) <
                        (unsigned long) (nb)))
                    victim = victim->bk_nextsize;

                /* Avoid removing the first entry for a size so that the skip
                   list does not have to be rerouted.  */
                if (victim != last (bin)
                        && chunksize_nomask (victim)
                        == chunksize_nomask (victim->fd))
                    victim = victim->fd;

                remainder_size = size - nb;
                unlink (av, victim, bck, fwd);

                /* Exhaust */
                if (remainder_size < MINSIZE)
                {
                    set_inuse_bit_at_offset (victim, size);
                    if (av != &main_arena)
                        set_non_main_arena (victim);
                }
                /* Split */
                else
                {
                    remainder = chunk_at_offset (victim, nb);
                    /* We cannot assume the unsorted list is empty and therefore
                       have to perform a complete insert here.  */
                    bck = unsorted_chunks (av);
                    fwd = bck->fd;
                    if (__glibc_unlikely (fwd->bk != bck))
                    {
                        errstr = "malloc(): corrupted unsorted chunks";
                        goto errout;
                    }
                    remainder->bk = bck;
                    remainder->fd = fwd;
                    bck->fd = remainder;
                    fwd->bk = remainder;
                    if (!in_smallbin_range (remainder_size))
                    {
                        remainder->fd_nextsize = NULL;
                        remainder->bk_nextsize = NULL;
                    }
                    set_head (victim, nb | PREV_INUSE |
                              (av != &main_arena ? NON_MAIN_ARENA : 0));
                    set_head (remainder, remainder_size | PREV_INUSE);
                    set_foot (remainder, remainder_size);
                }
                check_malloced_chunk (av, victim, nb);
                void *p = chunk2mem (victim);
                alloc_perturb (p, bytes);
                return p;
            }
        }

        /*
           Search for a chunk by scanning bins, starting with next largest
           bin. This search is strictly by best-fit; i.e., the smallest
           (with ties going to approximately the least recently used) chunk
           that fits is selected.

           The bitmap avoids needing to check that most blocks are nonempty.
           The particular case of skipping all bins during warm-up phases
           when no chunks have been returned yet is faster than it might look.
         */

        ++idx;
        bin = bin_at (av, idx);
        block = idx2block (idx);
        map = av->binmap[block];
        bit = idx2bit (idx);

        for (;; )
        {
            /* Skip rest of block if there are no more set bits in this block.  */
            if (bit > map || bit == 0)
            {
                do
                {
                    if (++block >= BINMAPSIZE) /* out of bins */
                        goto use_top;
                }
                while ((map = av->binmap[block]) == 0);

                bin = bin_at (av, (block << BINMAPSHIFT));
                bit = 1;
            }

            /* Advance to bin with set bit. There must be one. */
            while ((bit & map) == 0)
            {
                bin = next_bin (bin);
                bit <<= 1;
                assert (bit != 0);
            }

            /* Inspect the bin. It is likely to be non-empty */
            victim = last (bin);

            /*  If a false alarm (empty bin), clear the bit. */
            if (victim == bin)
            {
                av->binmap[block] = map &= ~bit; /* Write through */
                bin = next_bin (bin);
                bit <<= 1;
            }

            else
            {
                size = chunksize (victim);

                /*  We know the first chunk in this bin is big enough to use. */
                assert ((unsigned long) (size) >= (unsigned long) (nb));

                remainder_size = size - nb;

                /* unlink */
                unlink (av, victim, bck, fwd);

                /* Exhaust */
                if (remainder_size < MINSIZE)
                {
                    set_inuse_bit_at_offset (victim, size);
                    if (av != &main_arena)
                        set_non_main_arena (victim);
                }

                /* Split */
                else
                {
                    remainder = chunk_at_offset (victim, nb);

                    /* We cannot assume the unsorted list is empty and therefore
                       have to perform a complete insert here.  */
                    bck = unsorted_chunks (av);
                    fwd = bck->fd;
                    if (__glibc_unlikely (fwd->bk != bck))
                    {
                        errstr = "malloc(): corrupted unsorted chunks 2";
                        goto errout;
                    }
                    remainder->bk = bck;
                    remainder->fd = fwd;
                    bck->fd = remainder;
                    fwd->bk = remainder;

                    /* advertise as last remainder */
                    if (in_smallbin_range (nb))
                        av->last_remainder = remainder;
                    if (!in_smallbin_range (remainder_size))
                    {
                        remainder->fd_nextsize = NULL;
                        remainder->bk_nextsize = NULL;
                    }
                    set_head (victim, nb | PREV_INUSE |
                              (av != &main_arena ? NON_MAIN_ARENA : 0));
                    set_head (remainder, remainder_size | PREV_INUSE);
                    set_foot (remainder, remainder_size);
                }
                check_malloced_chunk (av, victim, nb);
                void *p = chunk2mem (victim);
                alloc_perturb (p, bytes);
                return p;
            }
        }

use_top:
        /*
           If large enough, split off the chunk bordering the end of memory
           (held in av->top). Note that this is in accord with the best-fit
           search rule.  In effect, av->top is treated as larger (and thus
           less well fitting) than any other available chunk since it can
           be extended to be as large as necessary (up to system
           limitations).

           We require that av->top always exists (i.e., has size >=
           MINSIZE) after initialization, so if it would otherwise be
           exhausted by current request, it is replenished. (The main
           reason for ensuring it exists is that we may need MINSIZE space
           to put in fenceposts in sysmalloc.)
         */

        victim = av->top;
        size = chunksize (victim);

        if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        {
            remainder_size = size - nb;
            remainder = chunk_at_offset (victim, nb);
            av->top = remainder;
            set_head (victim, nb | PREV_INUSE |
                      (av != &main_arena ? NON_MAIN_ARENA : 0));
            set_head (remainder, remainder_size | PREV_INUSE);

            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
        }

        /* When we are using atomic ops to free fast chunks we can get
           here for all block sizes.  */
        else if (have_fastchunks (av))
        {
            malloc_consolidate (av);
            /* restore original bin index */
            if (in_smallbin_range (nb))
                idx = smallbin_index (nb);
            else
                idx = largebin_index (nb);
        }

        /*
           Otherwise, relay to handle system-dependent cases
         */
        else
        {
            void *p = sysmalloc (nb, av);
            if (p != NULL)
                alloc_perturb (p, bytes);
            return p;
        }
    }
}

//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////

static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
    INTERNAL_SIZE_T size;        /* its size */
    mfastbinptr *fb;             /* associated fastbin */
    mchunkptr nextchunk;         /* next contiguous chunk */
    INTERNAL_SIZE_T nextsize;    /* its size */
    int nextinuse;               /* true if nextchunk is used */
    INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
    mchunkptr bck;               /* misc temp for linking */
    mchunkptr fwd;               /* misc temp for linking */

    const char *errstr = NULL;
    int locked = 0;

    size = chunksize (p);

    /* Little security check which won't hurt performance: the
       allocator never wrapps around at the end of the address space.
       Therefore we can exclude some size values which might appear
       here by accident or by "design" from some intruder.  */
    if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
            || __builtin_expect (misaligned_chunk (p), 0))
    {
        errstr = "free(): invalid pointer";
errout:
        if (!have_lock && locked)
            __libc_lock_unlock (av->mutex);
        malloc_printerr (check_action, errstr, chunk2mem (p), av);
        return;
    }
    
    /*****MINSIZE check*****/
    /* We know that each chunk is at least MINSIZE bytes in size or a
       multiple of MALLOC_ALIGNMENT.  */
    if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    {
        errstr = "free(): invalid size";
        goto errout;
    }

    check_inuse_chunk(av, p);

#if USE_TCACHE
    {
        size_t tc_idx = csize2tidx (size);

        if (tcache
                && tc_idx < mp_.tcache_bins
                && tcache->counts[tc_idx] < mp_.tcache_count)
        {
            tcache_put (p, tc_idx);
            return;
        }
    }
#endif

    /*
      If eligible, place chunk on a fastbin so it can be found
      and used quickly in malloc.
    */

    if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
            /*
            If TRIM_FASTBINS set, don't place chunks
            bordering top into fastbins
                 */
            && (chunk_at_offset(p, size) != av->top)
#endif
       ) {

        if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
                              <= 2 * SIZE_SZ, 0)
                || __builtin_expect (chunksize (chunk_at_offset (p, size))
                                     >= av->system_mem, 0))
        {
            /* We might not have a lock at this point and concurrent modifications
               of system_mem might have let to a false positive.  Redo the test
               after getting the lock.  */
               
            /***** next size check (fast) *****/
            if (have_lock
                    || ({ assert (locked == 0);
                          __libc_lock_lock (av->mutex);
                          locked = 1;
                          chunksize_nomask (chunk_at_offset (p, size)) <= 2 * SIZE_SZ
                          || chunksize (chunk_at_offset (p, size)) >= av->system_mem;
                        }))
            {
                errstr = "free(): invalid next size (fast)";
                goto errout;
            }
            if (! have_lock)
            {
                __libc_lock_unlock (av->mutex);
                locked = 0;
            }
        }

        free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

        set_fastchunks(av);
        unsigned int idx = fastbin_index(size);
        fb = &fastbin (av, idx);

        /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
        mchunkptr old = *fb, old2;
        unsigned int old_idx = ~0u;
        do
        {
            /***** double free check *****/
            /* Check that the top of the bin is not the record we are going to add
               (i.e., double free).  */
            if (__builtin_expect (old == p, 0))
            {
                errstr = "double free or corruption (fasttop)";
                goto errout;
            }
            /* Check that size of fastbin chunk at the top is the same as
               size of the chunk that we are adding.  We can dereference OLD
               only if we have the lock, otherwise it might have already been
               deallocated.  See use of OLD_IDX below for the actual check.  */
            if (have_lock && old != NULL)
                old_idx = fastbin_index(chunksize(old));
            p->fd = old2 = old;
        }
        while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);

        if (have_lock && old != NULL && __builtin_expect (old_idx != idx, 0))
        {
            errstr = "invalid fastbin entry (free)";
            goto errout;
        }
    }

    /*
      Consolidate other non-mmapped chunks as they arrive.
    */

    else if (!chunk_is_mmapped(p)) {
        if (! have_lock) {
            __libc_lock_lock (av->mutex);
            locked = 1;
        }

        nextchunk = chunk_at_offset(p, size);

        /* Lightweight tests: check whether the block is already the
           top block.  */
        if (__glibc_unlikely (p == av->top))
        {
            errstr = "double free or corruption (top)";
            goto errout;
        }
        /* Or whether the next chunk is beyond the boundaries of the arena.  */
        if (__builtin_expect (contiguous (av)
                              && (char *) nextchunk
                              >= ((char *) av->top + chunksize(av->top)), 0))
        {
            errstr = "double free or corruption (out)";
            goto errout;
        }
        /* Or whether the block is actually not marked used.  */
        if (__glibc_unlikely (!prev_inuse(nextchunk)))
        {
            errstr = "double free or corruption (!prev)";
            goto errout;
        }
        
        /***** next size check (normal) *****/
        nextsize = chunksize(nextchunk);
        if (__builtin_expect (chunksize_nomask (nextchunk) <= 2 * SIZE_SZ, 0)
                || __builtin_expect (nextsize >= av->system_mem, 0))
        {
            errstr = "free(): invalid next size (normal)";
            goto errout;
        }

        free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

        /* consolidate backward */
        if (!prev_inuse(p)) {
            prevsize = prev_size (p);
            size += prevsize;
            p = chunk_at_offset(p, -((long) prevsize));
            unlink(av, p, bck, fwd);
        }

        if (nextchunk != av->top) {
            /* get and clear inuse bit */
            nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

            /* consolidate forward */
            if (!nextinuse) {
                unlink(av, nextchunk, bck, fwd);
                size += nextsize;
            } else
                clear_inuse_bit_at_offset(nextchunk, 0);

            /***** unsorted bin link *****/
            /*
            Place the chunk in unsorted chunk list. Chunks are
            not placed into regular bins until after they have
            been given one chance to be used in malloc.
                 */

            bck = unsorted_chunks(av);
            fwd = bck->fd;
            if (__glibc_unlikely (fwd->bk != bck))
            {
                errstr = "free(): corrupted unsorted chunks";
                goto errout;
            }
            p->fd = fwd;
            p->bk = bck;
            if (!in_smallbin_range(size))
            {
                p->fd_nextsize = NULL;
                p->bk_nextsize = NULL;
            }
            bck->fd = p;
            fwd->bk = p;

            set_head(p, size | PREV_INUSE);
            set_foot(p, size);

            check_free_chunk(av, p);
        }

        /*
          If the chunk borders the current high end of memory,
          consolidate into top
        */

        else {
            size += nextsize;
            set_head(p, size | PREV_INUSE);
            av->top = p;
            check_chunk(av, p);
        }

        /*
          If freeing a large space, consolidate possibly-surrounding
          chunks. Then, if the total unused topmost memory exceeds trim
          threshold, ask malloc_trim to reduce top.

          Unless max_fast is 0, we don't know if there are fastbins
          bordering top, so we cannot tell for sure whether threshold
          has been reached unless fastbins are consolidated.  But we
          don't want to consolidate on each free.  As a compromise,
          consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
          is reached.
        */

        if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
            if (have_fastchunks(av))
                malloc_consolidate(av);

            if (av == &main_arena) {
#ifndef MORECORE_CANNOT_TRIM
                if ((unsigned long)(chunksize(av->top)) >=
                        (unsigned long)(mp_.trim_threshold))
                    systrim(mp_.top_pad, av);
#endif
            } else {
                /* Always try heap_trim(), even if the top chunk is not
                   large, because the corresponding heap might go away.  */
                heap_info *heap = heap_for_ptr(top(av));

                assert(heap->ar_ptr == av);
                heap_trim(heap, mp_.top_pad);
            }
        }

        if (! have_lock) {
            assert (locked);
            __libc_lock_unlock (av->mutex);
        }
    }
    /*
      If the chunk was allocated via mmap, release via munmap().
    */

    else {
        munmap_chunk (p);
    }
}

//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////

/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            \
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr (check_action, "corrupted size vs. prev_size", P, AV);  \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {								      \
        FD->bk = BK;							      \
        BK->fd = FD;							      \
        if (!in_smallbin_range (chunksize_nomask (P))			      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      \
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
	      malloc_printerr (check_action,				      \
			       "corrupted double-linked list (not small)",    \
			       P, AV);					      \
            if (FD->fd_nextsize == NULL) {				      \
                if (P->fd_nextsize == P)				      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                else {							      \
                    FD->fd_nextsize = P->fd_nextsize;			      \
                    FD->bk_nextsize = P->bk_nextsize;			      \
                    P->fd_nextsize->bk_nextsize = FD;			      \
                    P->bk_nextsize->fd_nextsize = FD;			      \
                  }							      \
              } else {							      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }								      \
          }								      \
      }									      \
}