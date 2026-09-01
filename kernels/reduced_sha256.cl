//kernels\reduced_sha256.cl
// Research-only kernel. It reuses sha256d80 from sha256d.cl when concatenated
// by a research host and aggregates bit counts on-device.
__kernel void aggregate_reduced_sha256d(__global const uchar* prefix,
                                        uint nonce_start,
                                        uint nonce_count,
                                        uint rounds,
                                        volatile __global uint* bit_counts) {
  uint gid=(uint)get_global_id(0);
  if(gid>=nonce_count)return;
  uint nonce=nonce_start+gid;
  uchar header[80];
  for(uint i=0;i<76;i++)header[i]=prefix[i];
  header[76]=(uchar)nonce;header[77]=(uchar)(nonce>>8);header[78]=(uchar)(nonce>>16);header[79]=(uchar)(nonce>>24);
  uint hash[8];sha256d80(header,hash,rounds);
  for(uint word=0;word<8;word++)for(uint bit=0;bit<32;bit++)if((hash[word]>>bit)&1U)atomic_inc(bit_counts+word*32+bit);
}
