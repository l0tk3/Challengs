file1=open("./uprobe","rb+").read()
file2=open("./uprobepart","wb+")
file2.write(file1[0x31050:])
file2.close()