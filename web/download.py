import urllib2



url = "http://cn.download.nvidia.com/XFree86/Linux-x86/352.41/NVIDIA-Linux-x86-352.41.run"
file = open("NVIDIA-Linux-x86-352.41.run","w")
target = urllib2.urlopen(url)
file.write(target.read())
file.close()
target.close()