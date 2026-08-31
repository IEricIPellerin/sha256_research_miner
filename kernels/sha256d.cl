// SHA256d over an 80-byte Bitcoin header. The host supplies the first 76
// bytes; gid selects the little-endian nonce. Candidate output is bounded.

__constant uint K[64] = {
  0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
  0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
  0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
  0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
  0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
  0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
  0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
  0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};

uint ror32(uint x, uint n) { return rotate(x, (uint)(32U - n)); }
uint read_be(__private const uchar* p) { return ((uint)p[0]<<24)|((uint)p[1]<<16)|((uint)p[2]<<8)|(uint)p[3]; }

void compress(__private uint state[8], __private const uchar block[64], uint rounds) {
  uint w[64];
  for (uint i=0;i<16;i++) w[i]=read_be(block+i*4);
  for (uint i=16;i<64;i++) {
    uint s0=ror32(w[i-15],7)^ror32(w[i-15],18)^(w[i-15]>>3);
    uint s1=ror32(w[i-2],17)^ror32(w[i-2],19)^(w[i-2]>>10);
    w[i]=w[i-16]+s0+w[i-7]+s1;
  }
  uint a=state[0],b=state[1],c=state[2],d=state[3],e=state[4],f=state[5],g=state[6],h=state[7];
  for(uint i=0;i<rounds;i++) {
    uint s1=ror32(e,6)^ror32(e,11)^ror32(e,25);
    uint ch=(e&f)^((~e)&g);
    uint t1=h+s1+ch+K[i]+w[i];
    uint s0=ror32(a,2)^ror32(a,13)^ror32(a,22);
    uint maj=(a&b)^(a&c)^(b&c);
    uint t2=s0+maj;
    h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
  }
  state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
}

void sha256d80(__private uchar header[80], __private uint output[8], uint rounds) {
  uint first[8]={0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
  uchar block[64];
  for(uint i=0;i<64;i++) block[i]=header[i];
  compress(first,block,rounds);
  for(uint i=0;i<64;i++) block[i]=0;
  for(uint i=0;i<16;i++) block[i]=header[64+i];
  block[16]=0x80; block[62]=0x02; block[63]=0x80;
  compress(first,block,rounds);

  for(uint i=0;i<64;i++) block[i]=0;
  for(uint i=0;i<8;i++) { block[i*4]=(uchar)(first[i]>>24);block[i*4+1]=(uchar)(first[i]>>16);block[i*4+2]=(uchar)(first[i]>>8);block[i*4+3]=(uchar)first[i]; }
  block[32]=0x80; block[62]=0x01; block[63]=0x00;
  output[0]=0x6a09e667U;output[1]=0xbb67ae85U;output[2]=0x3c6ef372U;output[3]=0xa54ff53aU;
  output[4]=0x510e527fU;output[5]=0x9b05688cU;output[6]=0x1f83d9abU;output[7]=0x5be0cd19U;
  compress(output,block,rounds);
}

int meets_target(__private uint hash[8], __global const uchar* target) {
  for(uint i=0;i<8;i++) {
    uint x=hash[7-i];
    uint h=((x&0x000000ffU)<<24)|((x&0x0000ff00U)<<8)|((x&0x00ff0000U)>>8)|((x&0xff000000U)>>24);
    uint t=((uint)target[i*4]<<24)|((uint)target[i*4+1]<<16)|((uint)target[i*4+2]<<8)|(uint)target[i*4+3];
    if(h<t)return 1;if(h>t)return 0;
  }
  return 1;
}

__kernel void sha256d_scan(__global const uchar* prefix, uint nonce_start, uint nonce_count,
                           __global const uchar* target, volatile __global uint* candidate_count,
                           __global uint* candidate_nonces) {
  uint gid=(uint)get_global_id(0);
  if(gid>=nonce_count)return;
  uint nonce=nonce_start+gid;
  uchar header[80];
  for(uint i=0;i<76;i++)header[i]=prefix[i];
  header[76]=(uchar)nonce;header[77]=(uchar)(nonce>>8);header[78]=(uchar)(nonce>>16);header[79]=(uchar)(nonce>>24);
  uint hash[8];sha256d80(header,hash,64);
  if(meets_target(hash,target)) { uint slot=atomic_inc(candidate_count); if(slot<64)candidate_nonces[slot]=nonce; }
}

// Deterministic validation path: returns all eight digest words for each
// header. It is used by the CPU/GPU bit-for-bit test, never by live mining.
__kernel void sha256d_vectors(__global const uchar* prefix, uint nonce_start,
                              uint nonce_count, __global uint* digests) {
  uint gid=(uint)get_global_id(0);
  if(gid>=nonce_count)return;
  uint nonce=nonce_start+gid;
  uchar header[80];
  for(uint i=0;i<76;i++)header[i]=prefix[i];
  header[76]=(uchar)nonce;header[77]=(uchar)(nonce>>8);header[78]=(uchar)(nonce>>16);header[79]=(uchar)(nonce>>24);
  uint hash[8];sha256d80(header,hash,64);
  for(uint i=0;i<8;i++)digests[gid*8+i]=hash[i];
}
