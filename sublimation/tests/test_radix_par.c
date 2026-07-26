// test_radix_par.c -- parallel MSD radix: differential vs std qsort, all types.
//
// Sorts uniform and skewed random past SUB_PAR_MIN (so the parallel frame path
// runs) through sub_radix_sort_par_<T> and requires the result to match a
// qsort'd copy (ints: byte-identical; floats: numeric-ascending + bit-multiset,
// for -0.0/+0.0 ties). Built plain and under ThreadSanitizer by run.py.
#define _POSIX_C_SOURCE 200809L
#include "internal/radix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int failures = 0;
#define CHECK(c,m) do{ if(!(c)){ fprintf(stderr,"FAIL: %s (%s:%d)\n",m,__FILE__,__LINE__); failures++; } }while(0)

static uint64_t rs = 0x100000001b3ull;
static uint64_t xr(void){ rs^=rs<<13; rs^=rs>>7; rs^=rs<<17; return rs; }

static size_t g_n = 500000;
#define WORKERS 4

#define GEN(T, SUF) \
static int SUF##_cmp(const void*x,const void*y){ T a=*(const T*)x,b=*(const T*)y; return (a>b)-(a<b);} \
static void run_##SUF(const char*shape, void(*fill)(T*,size_t)){ \
    size_t n=g_n; T *a=malloc(n*sizeof(T)),*o=malloc(n*sizeof(T)); \
    if(!a||!o){CHECK(0,"alloc");free(a);free(o);return;} \
    fill(a,n); memcpy(o,a,n*sizeof(T)); qsort(o,n,sizeof(T),SUF##_cmp); \
    sub_radix_sort_par_##SUF(a,n,WORKERS); \
    if(memcmp(a,o,n*sizeof(T))!=0){ fprintf(stderr,"  %s %s: != oracle\n",#SUF,shape); CHECK(0,#SUF);} \
    free(a);free(o);} \
static void uni_##SUF(T*a,size_t n){ for(size_t i=0;i<n;i++) a[i]=(T)(int64_t)xr(); } \
static void skew_##SUF(T*a,size_t n){ for(size_t i=0;i<n;i++){ uint64_t r=xr()%100000ull; a[i]=(T)(int64_t)(r*r); } }
GEN(int32_t,  i32)
GEN(int64_t,  i64)
GEN(uint32_t, u32)
GEN(uint64_t, u64)

static int u64b_cmp(const void*x,const void*y){ uint64_t a=*(const uint64_t*)x,b=*(const uint64_t*)y; return (a>b)-(a<b);}
static int u32b_cmp(const void*x,const void*y){ uint32_t a=*(const uint32_t*)x,b=*(const uint32_t*)y; return (a>b)-(a<b);}
static void uni_f64(double*a,size_t n){ for(size_t i=0;i<n;i++) a[i]=(double)(int64_t)xr()*1e-3; }
static void skew_f64(double*a,size_t n){ for(size_t i=0;i<n;i++){ double r=(double)(xr()%1000000u)/1e6; a[i]=r*r*r*((xr()&1)?-1.0:1.0); } }
static void uni_f32(float*a,size_t n){ for(size_t i=0;i<n;i++) a[i]=(float)(int32_t)xr()*1e-2f; }
static void skew_f32(float*a,size_t n){ for(size_t i=0;i<n;i++){ float r=(float)(xr()%1000000u)/1e6f; a[i]=r*r*r*((xr()&1)?-1.0f:1.0f); } }
static void run_f64(const char*s, void(*f)(double*,size_t)){
    size_t n=g_n; double*a=malloc(n*8); uint64_t*bi=malloc(n*8),*bo=malloc(n*8);
    if(!a||!bi||!bo){CHECK(0,"alloc");free(a);free(bi);free(bo);return;}
    f(a,n); memcpy(bi,a,n*8); sub_radix_sort_par_f64(a,n,WORKERS); memcpy(bo,a,n*8);
    for(size_t i=1;i<n;i++) if(a[i-1]>a[i]){fprintf(stderr,"  f64 %s: not ascending\n",s);CHECK(0,"f64 asc");break;}
    qsort(bi,n,8,u64b_cmp); qsort(bo,n,8,u64b_cmp); CHECK(memcmp(bi,bo,n*8)==0,"f64 multiset");
    free(a);free(bi);free(bo);}
static void run_f32(const char*s, void(*f)(float*,size_t)){
    size_t n=g_n; float*a=malloc(n*4); uint32_t*bi=malloc(n*4),*bo=malloc(n*4);
    if(!a||!bi||!bo){CHECK(0,"alloc");free(a);free(bi);free(bo);return;}
    f(a,n); memcpy(bi,a,n*4); sub_radix_sort_par_f32(a,n,WORKERS); memcpy(bo,a,n*4);
    for(size_t i=1;i<n;i++) if(a[i-1]>a[i]){fprintf(stderr,"  f32 %s: not ascending\n",s);CHECK(0,"f32 asc");break;}
    qsort(bi,n,4,u32b_cmp); qsort(bo,n,4,u32b_cmp); CHECK(memcmp(bi,bo,n*4)==0,"f32 multiset");
    free(a);free(bi);free(bo);}

int main(int argc, char **argv){
    if(argc>1){ long v=atol(argv[1]); if(v>1) g_n=(size_t)v; }
    run_i32("uniform",uni_i32); run_i32("skewed",skew_i32);
    run_i64("uniform",uni_i64); run_i64("skewed",skew_i64);
    run_u32("uniform",uni_u32); run_u32("skewed",skew_u32);
    run_u64("uniform",uni_u64); run_u64("skewed",skew_u64);
    run_f32("uniform",uni_f32); run_f32("skewed",skew_f32);
    run_f64("uniform",uni_f64); run_f64("skewed",skew_f64);
    if(failures){ fprintf(stderr,"test_radix_par: %d FAILED\n",failures); return 1; }
    printf("test_radix_par: OK\n");
    return 0;
}
