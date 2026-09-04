//kernels\header_space_map.cl
// Research-only exact zone mapper. One workgroup owns one statistical zone;
// all per-hash state is private and only the reduced zone record leaves the GPU.

__constant uint HS_K[64] = {
  0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
  0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
  0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
  0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
  0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
  0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
  0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
  0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};

uint hs_ror(uint value, uint bits) { return rotate(value, (uint)(32U - bits)); }
uint hs_read_be(__global const uchar* bytes) {
  return ((uint)bytes[0] << 24U) | ((uint)bytes[1] << 16U) |
         ((uint)bytes[2] << 8U) | (uint)bytes[3];
}
uint hs_bswap(uint value) {
  return ((value & 0x000000ffU) << 24U) | ((value & 0x0000ff00U) << 8U) |
         ((value & 0x00ff0000U) >> 8U) | ((value & 0xff000000U) >> 24U);
}

void hs_initial(__private uint state[8]) {
  state[0]=0x6a09e667U;state[1]=0xbb67ae85U;state[2]=0x3c6ef372U;state[3]=0xa54ff53aU;
  state[4]=0x510e527fU;state[5]=0x9b05688cU;state[6]=0x1f83d9abU;state[7]=0x5be0cd19U;
}

void hs_compress(__private uint state[8], __private uint words[16]) {
  uint w[64];
  for (uint i=0;i<16U;++i) w[i]=words[i];
  for (uint i=16U;i<64U;++i) {
    uint s0=hs_ror(w[i-15U],7U)^hs_ror(w[i-15U],18U)^(w[i-15U]>>3U);
    uint s1=hs_ror(w[i-2U],17U)^hs_ror(w[i-2U],19U)^(w[i-2U]>>10U);
    w[i]=w[i-16U]+s0+w[i-7U]+s1;
  }
  uint a=state[0],b=state[1],c=state[2],d=state[3];
  uint e=state[4],f=state[5],g=state[6],h=state[7];
  for(uint i=0;i<64U;++i) {
    uint s1=hs_ror(e,6U)^hs_ror(e,11U)^hs_ror(e,25U);
    uint choice=(e&f)^((~e)&g);
    uint temp1=h+s1+choice+HS_K[i]+w[i];
    uint s0=hs_ror(a,2U)^hs_ror(a,13U)^hs_ror(a,22U);
    uint majority=(a&b)^(a&c)^(b&c);
    uint temp2=s0+majority;
    h=g;g=f;f=e;e=d+temp1;d=c;c=b;b=a;a=temp1+temp2;
  }
  state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;
  state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
}

void hs_midstate(__global const uchar* prefix, __private uint state[8]) {
  uint words[16];
  for(uint i=0;i<16U;++i) words[i]=hs_read_be(prefix+i*4U);
  hs_initial(state);
  hs_compress(state,words);
}

void hs_sha256d(__global const uchar* prefix,
                __private const uint midstate[8],
                uint nonce,
                __private uint digest[8]) {
  uint words[16];
  words[0]=hs_read_be(prefix+64U);
  words[1]=hs_read_be(prefix+68U);
  words[2]=hs_read_be(prefix+72U);
  words[3]=hs_bswap(nonce);
  words[4]=0x80000000U;
  for(uint i=5U;i<15U;++i) words[i]=0U;
  words[15]=0x00000280U;
  for(uint i=0;i<8U;++i) digest[i]=midstate[i];
  hs_compress(digest,words);

  for(uint i=0;i<8U;++i) words[i]=digest[i];
  words[8]=0x80000000U;
  for(uint i=9U;i<15U;++i) words[i]=0U;
  words[15]=0x00000100U;
  hs_initial(digest);
  hs_compress(digest,words);
}

int hs_precedes(__private const uint left[8], uint left_nonce,
                __private const uint right[8], uint right_nonce) {
  for(uint i=0;i<8U;++i) {
    if(left[i]<right[i]) return 1;
    if(left[i]>right[i]) return 0;
  }
  return left_nonce<right_nonce;
}

int hs_meets_target(__private const uint value[8], __global const uchar* target) {
  for(uint i=0;i<8U;++i) {
    uint word=((uint)target[i*4U]<<24U)|((uint)target[i*4U+1U]<<16U)|
              ((uint)target[i*4U+2U]<<8U)|(uint)target[i*4U+3U];
    if(value[i]<word) return 1;
    if(value[i]>word) return 0;
  }
  return 1;
}

__kernel void map_header_space_zones(__global const uchar* prefix,
                                     __global const ulong* zone_starts,
                                     __global const ulong* zone_counts,
                                     __global const uchar* network_target,
                                     __global uint* output_minima,
                                     __global ulong* output_counts,
                                     __local uint* local_minima,
                                     __local ulong* local_counts) {
  const uint group=(uint)get_group_id(0);
  const uint lid=(uint)get_local_id(0);
  const uint local_size=(uint)get_local_size(0);
  const ulong start=zone_starts[group];
  const ulong count=zone_counts[group];
  uint midstate[8];
  hs_midstate(prefix,midstate);

  uint minimum[8];
  for(uint i=0;i<8U;++i) minimum[i]=0xffffffffU;
  uint minimum_nonce=0xffffffffU;
  ulong tails[8]={0UL,0UL,0UL,0UL,0UL,0UL,0UL,0UL};
  for(ulong offset=(ulong)lid;offset<count;offset+=(ulong)local_size) {
    const uint nonce=(uint)(start+offset);
    uint digest[8];
    hs_sha256d(prefix,midstate,nonce,digest);
    uint value[8];
    for(uint i=0;i<8U;++i) value[i]=hs_bswap(digest[7U-i]);
    const uint zeros=clz(value[0]);
    if(zeros>=26U) ++tails[0];
    if(zeros>=28U) ++tails[1];
    if(zeros>=30U) ++tails[2];
    if(zeros>=32U) ++tails[3];
    if(zeros>=34U) ++tails[4];
    if(zeros>=36U) ++tails[5];
    if(zeros>=38U) ++tails[6];
    if(hs_meets_target(value,network_target)) ++tails[7];
    if(hs_precedes(value,nonce,minimum,minimum_nonce)) {
      for(uint i=0;i<8U;++i) minimum[i]=value[i];
      minimum_nonce=nonce;
    }
  }

  const uint minimum_base=lid*9U;
  const uint count_base=lid*8U;
  for(uint i=0;i<8U;++i) local_minima[minimum_base+i]=minimum[i];
  local_minima[minimum_base+8U]=minimum_nonce;
  for(uint i=0;i<8U;++i) local_counts[count_base+i]=tails[i];
  barrier(CLK_LOCAL_MEM_FENCE);

  for(uint stride=local_size>>1U;stride>0U;stride>>=1U) {
    if(lid<stride) {
      const uint right_minimum_base=(lid+stride)*9U;
      uint right[8];
      for(uint i=0;i<8U;++i) right[i]=local_minima[right_minimum_base+i];
      const uint right_nonce=local_minima[right_minimum_base+8U];
      uint left[8];
      for(uint i=0;i<8U;++i) left[i]=local_minima[minimum_base+i];
      const uint left_nonce=local_minima[minimum_base+8U];
      if(hs_precedes(right,right_nonce,left,left_nonce)) {
        for(uint i=0;i<8U;++i) local_minima[minimum_base+i]=right[i];
        local_minima[minimum_base+8U]=right_nonce;
      }
      const uint right_count_base=(lid+stride)*8U;
      for(uint i=0;i<8U;++i) local_counts[count_base+i]+=local_counts[right_count_base+i];
    }
    barrier(CLK_LOCAL_MEM_FENCE);
  }

  if(lid==0U) {
    const uint output_minimum_base=group*9U;
    const uint output_count_base=group*8U;
    for(uint i=0;i<9U;++i) output_minima[output_minimum_base+i]=local_minima[i];
    for(uint i=0;i<8U;++i) output_counts[output_count_base+i]=local_counts[i];
  }
}
