# pcap_index
pcap store with index and search by flow

pcap store with index now capture packet with nta (rust cffi)

search pcap file with flow info by http like:
  wget  'http://127.0.0.1:50000/query?ip=172.16.150.53&port=21&proto=6' -O test.pcap

遗留问题：

1:还没进行性能调优

2:用带范围的参数搜索还有点问题 wget  'http://127.0.0.1:50000/query?ip=172.16.150.53-172.16.150.86&port=21&proto=6' -O test.pcap 

3:flow搜索时，offset合并优化减少磁盘寻址

4:单handler存储的同时进行搜索，耗时6秒，有优化空间

5:http按flow搜索，如果不存在时，等的时间会比较久，要优化

6:单handler的index线程cpu消耗过高，需要优化。

7:按总大小或者比例控制删除旧的文件和旧的index信息

8:删除旧的index信息，比如如果data文件被删掉

9:优化index格式，降低index占比
