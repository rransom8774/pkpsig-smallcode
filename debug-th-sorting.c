
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#ifdef MINIPKPSIG_SINGLEFILE
#include "minipkpsig.c"
#else
#include "minipkpsig-common.h"
#include "minipkpsig-symtypes.h"
#include "minipkpsig-pstypes.h"
#include "minipkpsig-paramsets-auto.h"
#include "minipkpsig-seclevels-auto.h"
#include "minipkpsig-treehash-auto.h"
#include "minipkpsig-sig-common.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <XKCP/SimpleFIPS202.h>
#include <png.h>

#ifndef MINIPKPSIG_SINGLEFILE
extern slt seclevels[];
extern ppst pkp_paramsets[];
extern symt symalgs[];
extern pst paramsets[];

typedef void (*sort_debug_cb)(tht *th, int nrs, int mergelen_l2, int chunkstart);
extern void NS(th_set_sort_debug_cb)(sort_debug_cb cb);
#endif

static tht th;
static tht *pth = &th;

static const pst *ps = NULL;

static u8 hbuf[TH_MAX_SORT_BLOCKS*4];

typedef struct {
    int x, y;
} point;
typedef struct {
    int x, y, w, h;
} rect;
static const u8 palette[] = {
    255, 255, 255,
      0,   0,   0,
    160, 160, 160,
    224, 224, 224,
      0,   0, 255,
};
enum {
IPAL_BG = 0,
IPAL_ELEMENT,
IPAL_ELEMENT_GHOST,
IPAL_BORDER,
IPAL_BORDER_CHUNK,
N_IPAL_ENTRIES
};
enum {
    IMG_ARRAY_ELT_MARK_SIZE = 8,
    IMG_ARRAY_LINE_WIDTH = 1,
    IMG_HEIGHT_ARRAY = TH_MAX_SORT_BLOCKS * IMG_ARRAY_ELT_MARK_SIZE,
    IMG_HEIGHT_MARKINGS = 64,
    IMG_HEIGHT = IMG_HEIGHT_ARRAY + IMG_HEIGHT_MARKINGS,
    IMG_WIDTH = TH_MAX_SORT_BLOCKS * (IMG_ARRAY_ELT_MARK_SIZE + IMG_ARRAY_LINE_WIDTH) + IMG_ARRAY_LINE_WIDTH,
};
static u8 image[IMG_HEIGHT][IMG_WIDTH];

static const char dot[8][8] = {
    "        ",
    "  xxxx  ",
    " xxxxxx ",
    " xxxxxx ",
    " xxxxxx ",
    " xxxxxx ",
    "  xxxx  ",
    "        ",
};

sv check_point_(const point *pt) {
    assert(pt->x >= 0);
    assert(pt->y >= 0);
    assert(pt->x < IMG_WIDTH);
    assert(pt->y < IMG_HEIGHT);
}
#define check_point(pt) check_point_(&(pt))

sv draw_dot_(const point *pt, u8 color) {
    int i, j;
    check_point_(pt);
    {
        const point lr = {pt->x + 7, pt->y + 7};
        check_point(lr);
    };
    FOR(i, 8) FOR(j, 8) {
        if (dot[j][i] != ' ') image[pt->y + j][pt->x + i] = color;
    }
}
#define draw_dot(pt, color) draw_dot_(&(pt), color)

sv draw_vline(int x, int yt, int yb, u8 color) {
    int i;

    {
        const point ul = {x, yt};
        const point lr = {x, yb};
        check_point(ul);
        check_point(lr);
    };

    for (i = yt; i <= yb; ++i) {
        image[i][x] = color;
    }
}

sv draw_array(int chunkstart, int mergelen) {
    int i;

    memset(image, IPAL_BG, sizeof(image));

    draw_vline(0, 0, IMG_HEIGHT_ARRAY, IPAL_BORDER);
    FOR(i, th.n_blocks + 50) {
        int x = 1 + i*(IMG_ARRAY_ELT_MARK_SIZE + IMG_ARRAY_LINE_WIDTH);
        int dot_y = IMG_ARRAY_ELT_MARK_SIZE *
                    ((th.n_blocks + 1) - (th.sortkeys[i] + 1));
        const point dot_ul = {x, dot_y};
        if (th.sortkeys[i] > th.n_blocks) continue;
        draw_vline(x+IMG_ARRAY_ELT_MARK_SIZE, 0, IMG_HEIGHT_ARRAY, IPAL_BORDER);
        draw_dot(dot_ul, IPAL_ELEMENT);
    }

    draw_vline(chunkstart * (IMG_ARRAY_ELT_MARK_SIZE + IMG_ARRAY_LINE_WIDTH),
               0, IMG_HEIGHT_ARRAY, IPAL_BORDER_CHUNK);
    draw_vline((chunkstart + mergelen) *
               (IMG_ARRAY_ELT_MARK_SIZE + IMG_ARRAY_LINE_WIDTH),
               0, IMG_HEIGHT_ARRAY, IPAL_BORDER_CHUNK);
}

sv draw_sort_debug_cb(tht *th, int nrs, int mergelen_l2, int chunkstart) {
    int mergelen = 1 << mergelen_l2;
    int width = 1 + (th->n_blocks+50)*(IMG_ARRAY_ELT_MARK_SIZE + IMG_ARRAY_LINE_WIDTH);
    int height = (th->n_blocks+1)*(IMG_ARRAY_ELT_MARK_SIZE);
    char namebuf[64];
    png_image img;

    draw_array(chunkstart, mergelen);

    snprintf(namebuf, sizeof(namebuf), "mergelen_l2_%d.png", mergelen_l2);
    namebuf[sizeof(namebuf)-1] = '\0';

    memset(&img, 0, sizeof(img));
    img.version = PNG_IMAGE_VERSION;
    img.width = width;
    img.height = height;
    img.format = PNG_FORMAT_RGB_COLORMAP;
    img.colormap_entries = N_IPAL_ENTRIES;
    png_image_write_to_file(&img, namebuf, 0, image, IMG_WIDTH, palette);
};

static uint32_t u32le_get(const uint8_t *p) {
  return (( ((uint32_t)p[0])       ) +
	        ((((uint32_t)p[1]) <<  8)) +
	        ((((uint32_t)p[2]) << 16)) +
	        ((((uint32_t)p[3]) << 24)));
};

static int compare_u32(const void *px, const void *py) {
    u32 x = *(u32*)px, y = *(u32*)py;
    if (x < y) {
        return -1;
    } else if (x == y) {
        return 0;
    } else /* x > y */ {
        return 1;
    }
}

static void init_array(int ips, const char *seed) {
    size_t seedlen = strlen(seed);
    const slt *ssl;
    int nrt, nrs, nrl;
    int i;

    ps = &(paramsets[ips]);
    ssl = &(seclevels[ps->ssl]);
    nrt = ps->nrtx + ssl->pbytes*8;
    nrl = ps->nrl; nrs = nrt - nrl;

    printf("ssl=%s, nrt=%d, nrs=%d, nrl=%d\n", ssl->name, nrt, nrs, nrl);

    th.n_blocks = nrt;

    /* sample a fixed-weight challenge vector */
    SHAKE256(hbuf, nrt*4, seed, seedlen);
    for (i = 0; i < nrt; ++i) {
        th.sortkeys[i] = (u32le_get(hbuf + 4*i) & ~(u32)1) | (i < nrl);
    }
    qsort(th.sortkeys, nrt, sizeof(u32), compare_u32);
    for (i = 1; i < nrt; ++i) {
        assert(th.sortkeys[i-1] <= th.sortkeys[i]);
    }

    /* now compute the list of indices input to th_sort_verify_C2 */
    for (i = 0; i < nrt; ++i) {
        u32 is_long_proof = th.sortkeys[i] & 1;
        th.sortkeys[i] = (is_long_proof << 16) | i;
    }
    qsort(th.sortkeys, nrt, sizeof(u32), compare_u32);
    for (i = 1; i < nrt; ++i) {
        assert(th.sortkeys[i-1] <= th.sortkeys[i]);
    }

    for (i = 0; i < nrt; ++i) {
        th.sortkeys[i] &= 0xFFFF;
    }
}

int main(int argc, char *argv[]) {
    init_array(15, "foo");
    minipkpsig_th_set_sort_debug_cb(draw_sort_debug_cb);
    th_sort_verifyC2(pth, ps);

    return 0;
}

