/*
 * Luis Figueiredo - why remake the wheel, this functions feets perfectly
 * and the credits still here :)
 */


/*
 * xvgifwr.c  -  handles writing of GIF files.  based on flgife.c and
 *               flgifc.c from the FBM Library, by Michael Maudlin
 *
 * Contains: 
 *   WriteGIF(fp, pic, ptype, w, h, rmap, gmap, bmap, numcols, colorstyle,
 *            comment)
 *
 * Note: slightly brain-damaged, in that it'll only write non-interlaced 
 *       GIF files (in the interests of speed, or something)
 *
 */



/*****************************************************************
 * Portions of this code Copyright (C) 1989 by Michael Mauldin.
 * Permission is granted to use this file in whole or in
 * part for any purpose, educational, recreational or commercial,
 * provided that this copyright notice is retained unchanged.
 * This software is available to all free of charge by anonymous
 * FTP and in the UUNET archives.
 *
 *
 * Authors:  Michael Mauldin (mlm@cs.cmu.edu)
 *           David Rowley (mgardi@watdcsu.waterloo.edu)
 *
 * Based on: compress.c - File compression ala IEEE Computer, June 1984.
 *
 *	Spencer W. Thomas       (decvax!harpo!utah-cs!utah-gr!thomas)
 *	Jim McKie               (decvax!mcvax!jim)
 *	Steve Davies            (decvax!vax135!petsd!peora!srd)
 *	Ken Turkowski           (decvax!decwrl!turtlevax!ken)
 *	James A. Woods          (decvax!ihnp4!ames!jaw)
 *	Joe Orost               (decvax!vax135!petsd!joe)
 *****************************************************************/
 

#include "outgif.h"

static int  __ILWS_Width, __ILWS_Height;
static int  __ILWS_curx, __ILWS_cury;
static long __ILWS_CountDown;
static int  __ILWS_Interlace;
//static unsigned char bw[2] = {0, 0xff};

static void __ILWS_putword     PARM((int, FILE *));
static void __ILWS_compress    PARM((int, FILE *, unsigned char *, int));
static void __ILWS_output      PARM((int));
static void __ILWS_cl_block    PARM((void));
static void __ILWS_cl_hash     PARM((count_int));
static void __ILWS_char_init   PARM((void));
static void __ILWS_char_out    PARM((int));
static void __ILWS_flush_char  PARM((void));


static unsigned char pc2nc[256],r1[256],g1[256],b1[256];


/*************************************************************/
int __ILWS_WriteGIF(FILE *fp, unsigned char *pic, int w, int h, unsigned char *rmap, unsigned char *gmap, unsigned char *bmap, int numcols, int colorstyle,int transparency,
	     char *comment)
{
  int   RWidth, RHeight;
  int   LeftOfs, TopOfs;
  int   ColorMapSize, InitCodeSize, Background, BitsPerPixel;
  int   i,j,nc;
  unsigned char *pic8;
  //unsigned char  rtemp[256],gtemp[256],btemp[256];

  pic8 = pic;



  __ILWS_Interlace = 0;
  Background = 0;


  for (i=0; i<256; i++) { pc2nc[i] = r1[i] = g1[i] = b1[i] = 0; }

  /* compute number of unique colors */
  nc = 0;

  for (i=0; i<numcols; i++) {
    /* see if color #i is already used */
    for (j=0; j<i; j++) {
      if (rmap[i] == rmap[j] && gmap[i] == gmap[j] && 
	  bmap[i] == bmap[j]) break;
    }

    if (j==i) {  /* wasn't found */
      pc2nc[i] = nc;
      r1[nc] = rmap[i];
      g1[nc] = gmap[i];
      b1[nc] = bmap[i];
      nc++;
    }
    else pc2nc[i] = pc2nc[j];
  }


  /* figure out 'BitsPerPixel' */
  for (i=1; i<8; i++)
    if ( (1<<i) >= nc) break;
  
  BitsPerPixel = i;

  ColorMapSize = 1 << BitsPerPixel;
	
  RWidth  = __ILWS_Width  = w;
  RHeight = __ILWS_Height = h;
  LeftOfs = TopOfs = 0;
	
  __ILWS_CountDown = w * h;    /* # of pixels we'll be doing */

  if (BitsPerPixel <= 1) InitCodeSize = 2;
                    else InitCodeSize = BitsPerPixel;

  __ILWS_curx = __ILWS_cury = 0;

  if (!fp) {
    fprintf(stderr,  "WriteGIF: file not open for writing\n" );
    return (1);
  }

  
  if (comment && strlen(comment) > (size_t) 0)
    fwrite("GIF89a", (size_t) 1, (size_t) 6, fp);    /* the GIF magic number */
  else
    fwrite("GIF87a", (size_t) 1, (size_t) 6, fp);    /* the GIF magic number */

  __ILWS_putword(RWidth, fp);           /* screen descriptor */
  __ILWS_putword(RHeight, fp);

  i = 0x80;	                 /* Yes, there is a color map */
  i |= (8-1)<<4;                 /* OR in the color resolution (hardwired 8) */
  i |= (BitsPerPixel - 1);       /* OR in the # of bits per pixel */
  fputc(i,fp);          

  fputc(Background, fp);         /* background color */

  fputc(0, fp);                  /* future expansion unsigned char */


  if (colorstyle == 1) {         /* greyscale */
    for (i=0; i<ColorMapSize; i++) {
      j = MONO(r1[i], g1[i], b1[i]);
      fputc(j, fp);
      fputc(j, fp);
      fputc(j, fp);
    }
  }
  else {
    for (i=0; i<ColorMapSize; i++) {       /* write out Global colormap */
      fputc(r1[i], fp);
      fputc(g1[i], fp);
      fputc(b1[i], fp);
    }
  }

  if (comment && strlen(comment) > (size_t) 0) {   /* write comment blocks */
    char *sp;
    int   i, blen;

    fputc(0x21, fp);     /* EXTENSION block */
	fputc(0xF9,fp);   // graphic control extension// Luis Figueiredo
	fputc(4,fp);    // blocksize
	fputc(0x1,fp); // transparency flag
	fputc(100,fp);// delay (unsigned?)
	fputc(100,fp);// delay (unsigned?)
	fputc(transparency,fp); // Luis figueiredo
	fputc(0, fp);    /* zero-length data subblock to end extension */
    fputc(0x21, fp);     /* EXTENSION block */
	fputc(0xFE, fp);     /* comment extension */
    sp = comment;
    while ( (blen=strlen(sp)) > 0) {
      if (blen>255) blen = 255;
      fputc(blen, fp);
      for (i=0; i<blen; i++, sp++) fputc(*sp, fp);
    }
    fputc(0, fp);    /* zero-length data subblock to end extension */
  }


  fputc( ',', fp );              /* image separator */

  /* Write the Image header */
  __ILWS_putword(LeftOfs, fp);
  __ILWS_putword(TopOfs,  fp);
  __ILWS_putword(__ILWS_Width,   fp);
  __ILWS_putword(__ILWS_Height,  fp);
  if (__ILWS_Interlace) fputc(0x40, fp);   /* Use Global Colormap, maybe Interlace */
            else fputc(0x00, fp);

  fputc(InitCodeSize, fp);
  __ILWS_compress(InitCodeSize+1, fp, pic8, w*h);

  fputc(0,fp);                      /* Write out a Zero-length packet (EOF) */
  fputc(';',fp);                    /* Write GIF file terminator */


  if (ferror(fp)) return -1;
  return (0);
}




/******************************/
static void __ILWS_putword(int w, FILE *fp)
{
  /* writes a 16-bit integer in GIF order (LSB first) */
  fputc(w & 0xff, fp);
  fputc((w>>8)&0xff, fp);
}




/***********************************************************************/


static unsigned long __ILWS_cur_accum = 0;
static int           __ILWS_cur_bits = 0;




#define min(a,b)        ((a>b) ? b : a)

#define XV_BITS	12    /* BITS was already defined on some systems */
#define MSDOS	1

#define HSIZE  5003            /* 80% occupancy */

typedef unsigned char   char_type;


static int __ILWS_n_bits;                    /* number of bits/code */
static int __ILWS_maxbits = XV_BITS;         /* user settable max # bits/code */
static int __ILWS_maxcode;                   /* maximum code, given n_bits */
static int __ILWS_maxmaxcode = 1 << XV_BITS; /* NEVER generate this */

#define MAXCODE(n_bits)     ( (1 << (n_bits)) - 1)

static  count_int      __ILWS_htab [HSIZE];
static  unsigned short __ILWS_codetab [HSIZE];
#define HashTabOf(i)   __ILWS_htab[i]
#define CodeTabOf(i)   __ILWS_codetab[i]

static int __ILWS_hsize = HSIZE;            /* for dynamic table sizing */

/*
 * To save much memory, we overlay the table used by compress() with those
 * used by decompress().  The tab_prefix table is the same size and type
 * as the codetab.  The tab_suffix table needs 2**BITS characters.  We
 * get this from the beginning of htab.  The output stack uses the rest
 * of htab, and contains characters.  There is plenty of room for any
 * possible stack (stack used to be 8000 characters).
 */

#define tab_prefixof(i) CodeTabOf(i)
#define tab_suffixof(i)        ((char_type *)(htab))[i]
#define de_stack               ((char_type *)&tab_suffixof(1<<XV_BITS))

static int __ILWS_free_ent = 0;                  /* first unused entry */

/*
 * block compression parameters -- after all codes are used up,
 * and compression rate changes, start over.
 */
static int __ILWS_clear_flg = 0;

static long int __ILWS_in_count = 1;            /* length of input */
static long int __ILWS_out_count = 0;           /* # of codes output (for debugging) */

/*
 * compress stdin to stdout
 *
 * Algorithm:  use open addressing double hashing (no chaining) on the 
 * prefix code / next character combination.  We do a variant of Knuth's
 * algorithm D (vol. 3, sec. 6.4) along with G. Knott's relatively-prime
 * secondary probe.  Here, the modular division first probe is gives way
 * to a faster exclusive-or manipulation.  Also do block compression with
 * an adaptive reset, whereby the code table is cleared when the compression
 * ratio decreases, but after the table fills.  The variable-length output
 * codes are re-sized at this point, and a special CLEAR code is generated
 * for the decompressor.  Late addition:  construct the table according to
 * file size for noticeable speed improvement on small files.  Please direct
 * questions about this implementation to ames!jaw.
 */

static int __ILWS_g_init_bits;
static FILE *__ILWS_g_outfile;

static int __ILWS_ClearCode;
static int __ILWS_EOFCode;


/********************************************************/
static void __ILWS_compress(int init_bits, FILE *outfile, unsigned char *data, int len)

{
  register long fcode;
  register int i = 0;
  register int c;
  register int ent;
  register int disp;
  register int hsize_reg;
  register int hshift;

  /*
   * Set up the globals:  g_init_bits - initial number of bits
   *                      g_outfile   - pointer to output file
   */
  __ILWS_g_init_bits = init_bits;
  __ILWS_g_outfile   = outfile;

  /* initialize 'compress' globals */
  __ILWS_maxbits = XV_BITS;
  __ILWS_maxmaxcode = 1<<XV_BITS;
  memset((char *) __ILWS_htab,0,    sizeof(__ILWS_htab));
  memset((char *) __ILWS_codetab,0, sizeof(__ILWS_codetab));
  __ILWS_hsize = HSIZE;
  __ILWS_free_ent = 0;
  __ILWS_clear_flg = 0;
  __ILWS_in_count = 1;
  __ILWS_out_count = 0;
  __ILWS_cur_accum = 0;
  __ILWS_cur_bits = 0;


  /*
   * Set up the necessary values
   */
  __ILWS_out_count = 0;
  __ILWS_clear_flg = 0;
  __ILWS_in_count = 1;
  __ILWS_maxcode = MAXCODE(__ILWS_n_bits = __ILWS_g_init_bits);

  __ILWS_ClearCode = (1 << (init_bits - 1));
  __ILWS_EOFCode = __ILWS_ClearCode + 1;
  __ILWS_free_ent = __ILWS_ClearCode + 2;

  __ILWS_char_init();
  ent = pc2nc[*data++];  
  len--;

  hshift = 0;
  for ( fcode = (long) __ILWS_hsize;  fcode < 65536L; fcode *= 2L )
    hshift++;
  hshift = 8 - hshift;                /* set hash code range bound */

  hsize_reg = __ILWS_hsize;
  __ILWS_cl_hash( (count_int) hsize_reg);            /* clear hash table */

  __ILWS_output(__ILWS_ClearCode);
    
  while (len) {
    c = pc2nc[*data++];  len--;
    __ILWS_in_count++;

    fcode = (long) ( ( (long) c << __ILWS_maxbits) + ent);
    i = (((int) c << hshift) ^ ent);    /* xor hashing */

    if ( HashTabOf (i) == fcode ) {
      ent = CodeTabOf (i);
      continue;
    }

    else if ( (long)HashTabOf (i) < 0 )      /* empty slot */
      goto nomatch;

    disp = hsize_reg - i;           /* secondary hash (after G. Knott) */
    if ( i == 0 )
      disp = 1;

probe:
    if ( (i -= disp) < 0 )
      i += hsize_reg;

    if ( HashTabOf (i) == fcode ) {
      ent = CodeTabOf (i);
      continue;
    }

    if ( (long)HashTabOf (i) >= 0 ) 
      goto probe;

nomatch:
    __ILWS_output(ent);
    __ILWS_out_count++;
    ent = c;

    if ( __ILWS_free_ent < __ILWS_maxmaxcode ) {
      CodeTabOf (i) = __ILWS_free_ent++; /* code -> hashtable */
      HashTabOf (i) = fcode;
    }
    else
      __ILWS_cl_block();
  }

  /* Put out the final code */
  __ILWS_output(ent);
  __ILWS_out_count++;
  __ILWS_output(__ILWS_EOFCode);
}


/*****************************************************************
 * TAG( output )
 *
 * Output the given code.
 * Inputs:
 *      code:   A n_bits-bit integer.  If == -1, then EOF.  This assumes
 *              that n_bits =< (long)wordsize - 1.
 * Outputs:
 *      Outputs code to the file.
 * Assumptions:
 *      Chars are 8 bits long.
 * Algorithm:
 *      Maintain a BITS character long buffer (so that 8 codes will
 * fit in it exactly).  Use the VAX insv instruction to insert each
 * code in turn.  When the buffer fills up empty it and start over.
 */

static
unsigned long __ILWS_masks[] = { 0x0000, 0x0001, 0x0003, 0x0007, 0x000F,
                                  0x001F, 0x003F, 0x007F, 0x00FF,
                                  0x01FF, 0x03FF, 0x07FF, 0x0FFF,
                                  0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF };

static void __ILWS_output(int code)
{
  __ILWS_cur_accum &= __ILWS_masks[__ILWS_cur_bits];

  if (__ILWS_cur_bits > 0)
    __ILWS_cur_accum |= ((long)code << __ILWS_cur_bits);
  else
    __ILWS_cur_accum = code;
	
  __ILWS_cur_bits += __ILWS_n_bits;

  while( __ILWS_cur_bits >= 8 ) {
    __ILWS_char_out( (int) (__ILWS_cur_accum & 0xff) );
    __ILWS_cur_accum >>= 8;
    __ILWS_cur_bits -= 8;
  }

  /*
   * If the next entry is going to be too big for the code size,
   * then increase it, if possible.
   */

  if (__ILWS_free_ent > __ILWS_maxcode || __ILWS_clear_flg) {

    if( __ILWS_clear_flg ) {
      __ILWS_maxcode = MAXCODE (__ILWS_n_bits = __ILWS_g_init_bits);
      __ILWS_clear_flg = 0;
    }
    else {
      __ILWS_n_bits++;
      if ( __ILWS_n_bits == __ILWS_maxbits )
	__ILWS_maxcode = __ILWS_maxmaxcode;
      else
	__ILWS_maxcode = MAXCODE(__ILWS_n_bits);
    }
  }
	
  if( code == __ILWS_EOFCode ) {
    /* At EOF, write the rest of the buffer */
    while( __ILWS_cur_bits > 0 ) {
      __ILWS_char_out( (int)(__ILWS_cur_accum & 0xff) );
      __ILWS_cur_accum >>= 8;
      __ILWS_cur_bits -= 8;
    }

    __ILWS_flush_char();
	
    fflush( __ILWS_g_outfile );

#ifdef FOO
    if( ferror( g_outfile ) ) 
      FatalError("unable to write GIF file");
#endif
  }
}


/********************************/
static void __ILWS_cl_block ()             /* table clear for block compress */
{
  /* Clear out the hash table */

  __ILWS_cl_hash ( (count_int) __ILWS_hsize );
  __ILWS_free_ent = __ILWS_ClearCode + 2;
  __ILWS_clear_flg = 1;

  __ILWS_output(__ILWS_ClearCode);
}


/********************************/
static void __ILWS_cl_hash(register count_int hsize)          /* reset code table */
{
  register count_int *htab_p = __ILWS_htab+hsize;
  register long i;
  register long m1 = -1;

  i = hsize - 16;
  do {                            /* might use Sys V memset(3) here */
    *(htab_p-16) = m1;
    *(htab_p-15) = m1;
    *(htab_p-14) = m1;
    *(htab_p-13) = m1;
    *(htab_p-12) = m1;
    *(htab_p-11) = m1;
    *(htab_p-10) = m1;
    *(htab_p-9) = m1;
    *(htab_p-8) = m1;
    *(htab_p-7) = m1;
    *(htab_p-6) = m1;
    *(htab_p-5) = m1;
    *(htab_p-4) = m1;
    *(htab_p-3) = m1;
    *(htab_p-2) = m1;
    *(htab_p-1) = m1;
    htab_p -= 16;
  } while ((i -= 16) >= 0);

  for ( i += 16; i > 0; i-- )
    *--htab_p = m1;
}


/******************************************************************************
 *
 * GIF Specific routines
 *
 ******************************************************************************/

/*
 * Number of characters so far in this 'packet'
 */
static int __ILWS_a_count;

/*
 * Set up the 'unsigned char output' routine
 */
static void __ILWS_char_init()
{
	__ILWS_a_count = 0;
}

/*
 * Define the storage for the packet accumulator
 */
static char __ILWS_accum[ 256 ];

/*
 * Add a character to the end of the current packet, and if it is 254
 * characters, flush the packet to disk.
 */
static void __ILWS_char_out(int c)
{
  __ILWS_accum[ __ILWS_a_count++ ] = c;
  if( __ILWS_a_count >= 254 ) 
    __ILWS_flush_char();
}

/*
 * Flush the packet to disk, and reset the accumulator
 */
static void __ILWS_flush_char()
{
  if( __ILWS_a_count > 0 ) {
    fputc(__ILWS_a_count, __ILWS_g_outfile );
    fwrite(__ILWS_accum, (size_t) 1, (size_t) __ILWS_a_count, __ILWS_g_outfile );
    __ILWS_a_count = 0;
  }
}	
