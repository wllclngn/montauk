// test_radix.c -- pure-random radix arm: differential vs std qsort, all types.
//
// Each type sorts uniform and skewed random through sub_radix_sort_<T> and must
// equal a qsort'd copy byte-for-byte (sortedness + multiset in one check).
// Signed fills span negatives and float fills span both signs and magnitudes,
// so the monotonic key flips (sign-bit for ints, IEEE total-order for floats)
// are exercised. NaN is out of scope: the public sort parks NaNs before this arm.
#define _POSIX_C_SOURCE 200809L
#include "internal/radix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int failures = 0;
#define CHECK(c,m) do{ if(!(c)){ fprintf(stderr,"FAIL: %s (%s:%d)\n",m,__FILE__,__LINE__); failures++; } }while(0)

static uint64_t rs = 0xcbf29ce484222325ull;
static uint64_t xr(void){ rs^=rs<<13; rs^=rs>>7; rs^=rs<<17; return rs; }

#define N 200000

#define GEN(T, SUF, CMP, FILL_UNI, FILL_SKEW) \
static int SUF##_cmp(const void*x,const void*y){ T a=*(const T*)x,b=*(const T*)y; return (a>b)-(a<b);} \
static void run_##SUF(const char*shape, void(*fill)(T*,size_t)){ \
    T *a=malloc(N*sizeof(T)),*o=malloc(N*sizeof(T)); \
    if(!a||!o){CHECK(0,"alloc");free(a);free(o);return;} \
    fill(a,N); memcpy(o,a,N*sizeof(T)); qsort(o,N,sizeof(T),SUF##_cmp); \
    sub_radix_sort_##SUF(a,N); \
    if(memcmp(a,o,N*sizeof(T))!=0){ fprintf(stderr,"  %s %s: != oracle\n",#SUF,shape); CHECK(0,#SUF);} \
    free(a);free(o);} \
static void FILL_UNI(T*a,size_t n){ for(size_t i=0;i<n;i++) a[i]=(T)(int64_t)xr(); } \
static void FILL_SKEW(T*a,size_t n){ for(size_t i=0;i<n;i++){ uint64_t r=xr()%100000ull; a[i]=(T)(int64_t)(r*r); } }

GEN(int32_t,  i32, i32, uni_i32, skew_i32)
GEN(int64_t,  i64, i64, uni_i64, skew_i64)
GEN(uint32_t, u32, u32, uni_u32, skew_u32)
GEN(uint64_t, u64, u64, uni_u64, skew_u64)

// Floats: numeric-ascending + bit-multiset (the float contract -- memcmp vs a
// naive qsort is wrong for -0.0/+0.0 ties). Uniform spans both signs; skewed
// clusters near zero. No int overflow: magnitudes come from double math.
static int u64bits_cmp(const void*x,const void*y){ uint64_t a=*(const uint64_t*)x,b=*(const uint64_t*)y; return (a>b)-(a<b);}
static int u32bits_cmp(const void*x,const void*y){ uint32_t a=*(const uint32_t*)x,b=*(const uint32_t*)y; return (a>b)-(a<b);}
static void uni_f64(double*a,size_t n){ for(size_t i=0;i<n;i++){ int64_t m=(int64_t)xr(); a[i]=(double)m*1e-3; } }
static void skew_f64(double*a,size_t n){ for(size_t i=0;i<n;i++){ double r=(double)(xr()%1000000u)/1e6; a[i]=r*r*r*((xr()&1)?-1.0:1.0); } }
static void uni_f32(float*a,size_t n){ for(size_t i=0;i<n;i++){ int32_t m=(int32_t)xr(); a[i]=(float)m*1e-2f; } }
static void skew_f32(float*a,size_t n){ for(size_t i=0;i<n;i++){ float r=(float)(xr()%1000000u)/1e6f; a[i]=r*r*r*((xr()&1)?-1.0f:1.0f); } }
static void run_f64(const char*s, void(*f)(double*,size_t)){
    double*a=malloc(N*8); uint64_t*bi=malloc(N*8),*bo=malloc(N*8);
    if(!a||!bi||!bo){CHECK(0,"alloc");free(a);free(bi);free(bo);return;}
    f(a,N); memcpy(bi,a,N*8); sub_radix_sort_f64(a,N); memcpy(bo,a,N*8);
    for(size_t i=1;i<N;i++) if(a[i-1]>a[i]){ fprintf(stderr,"  f64 %s: not ascending\n",s); CHECK(0,"f64 asc"); break; }
    qsort(bi,N,8,u64bits_cmp); qsort(bo,N,8,u64bits_cmp);
    CHECK(memcmp(bi,bo,N*8)==0,"f64 bit-multiset");
    free(a);free(bi);free(bo);}
static void run_f32(const char*s, void(*f)(float*,size_t)){
    float*a=malloc(N*4); uint32_t*bi=malloc(N*4),*bo=malloc(N*4);
    if(!a||!bi||!bo){CHECK(0,"alloc");free(a);free(bi);free(bo);return;}
    f(a,N); memcpy(bi,a,N*4); sub_radix_sort_f32(a,N); memcpy(bo,a,N*4);
    for(size_t i=1;i<N;i++) if(a[i-1]>a[i]){ fprintf(stderr,"  f32 %s: not ascending\n",s); CHECK(0,"f32 asc"); break; }
    qsort(bi,N,4,u32bits_cmp); qsort(bo,N,4,u32bits_cmp);
    CHECK(memcmp(bi,bo,N*4)==0,"f32 bit-multiset");
    free(a);free(bi);free(bo);}

int main(void){
    run_i32("uniform",uni_i32); run_i32("skewed",skew_i32);
    run_i64("uniform",uni_i64); run_i64("skewed",skew_i64);
    run_u32("uniform",uni_u32); run_u32("skewed",skew_u32);
    run_u64("uniform",uni_u64); run_u64("skewed",skew_u64);
    run_f32("uniform",uni_f32); run_f32("skewed",skew_f32);
    run_f64("uniform",uni_f64); run_f64("skewed",skew_f64);
    // small-n coarsen edge
    for (size_t n=0;n<=40;n++){ int64_t a[40],o[40]; for(size_t i=0;i<n;i++) a[i]=o[i]=(int64_t)xr();
        qsort(o,n,8,i64_cmp); sub_radix_sort_i64(a,n);
        if(n>1 && memcmp(a,o,n*8)!=0) CHECK(0,"i64 small-n"); }
    if(failures){ fprintf(stderr,"test_radix: %d FAILED\n",failures); return 1; }
    printf("test_radix: OK\n");
    return 0;
}
