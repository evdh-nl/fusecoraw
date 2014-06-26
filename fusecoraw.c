/*
 * File:    fusecoraw.c
 * Copyright (c) 2007 Vitaly "_Vi" Shukela
 * Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
 *
 * Contact Email: public_vi@tut.by
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *   
 * gcc -O2 `pkg-config fuse --cflags --libs` fusecoraw.c -o fusecoraw
 */

/* map file format:
	  signature:               filesize:
00000000  66 75 73 65 63 6f 77 0a  00 00 40 06 00 00 00 00  |fusecow...@.....|
	  block_size:              reserved:
00000010  00 20 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |. ..............|
	  actual map data begins here:
00000020  00 00 00 00 00 00 00 00  00 00 40 00 00 00 8C 01  |................|
	     ^   			 ^
	     00 - all 8 blocks unchanged;40 == 0b01000000 means one block was overridden here

 */

#define FUSE_USE_VERSION 26
#define _XOPEN_SOURCE 500
#define _FILE_OFFSET_BITS 64 
#define _LARGEFILE64_SOURCE

#include <sys/types.h>
#include <unistd.h>
#include <fuse.h>
#include <time.h>
#include <stdlib.h>
#include <error.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>  // for fprintf
#include <malloc.h> // for malloc
#include <sys/mman.h>


int fd;
int fd_write;
int fd_write_map;
char* mem_write_map;
size_t mem_write_map_size;

// copy-on-read vars.
int fd_read;
int fd_read_map;
char* mem_read_map;
size_t mem_read_map_size;
int read_only;

int block_size;
off64_t st_size;

char* copyup_buffer;

int get_map_size() {  
    int bytes_required = 32 + ((st_size / block_size + 1) / 8 + 1);	
    int page_size = getpagesize();
    return (bytes_required / page_size + 1) * page_size;
}

char write_map_get(long long int block) {
    long long int offset = 32 + block/8;    
    if(mem_write_map!=MAP_FAILED && offset > mem_write_map_size) {
	return 0;
    }
    char c=0;
    if(mem_write_map!=MAP_FAILED) {
    c = mem_write_map[offset];
    } else {
        pread64(fd_write_map, &c, 1, offset);
    }
    return (c & (1<<(block%8)))?1:0;
}

void write_map_set(long long int block, char val) {
    long long int offset = 32 + block/8;    
    if((mem_write_map!=MAP_FAILED) && (offset > mem_write_map_size) ) {
    munmap(mem_write_map, mem_write_map_size);
    mem_write_map_size = (block/8/getpagesize()+1)*getpagesize();
    ftruncate(fd_write_map, mem_write_map_size);
    mem_write_map = mmap(NULL, mem_write_map_size , PROT_READ|PROT_WRITE, MAP_SHARED, fd_write_map, 0);
    }
    char c;
    if(mem_write_map!=MAP_FAILED) {
    c = mem_write_map[offset];
    } else {
        pread64(fd_write_map, &c, 1, offset);
    }

    char mask = 1 << (block%8);
    c &= ~mask;
    if(val) {
	c |= mask;
    }

    if(mem_write_map!=MAP_FAILED) {
    mem_write_map[offset]=c;
    } else {
        pwrite64(fd_write_map, &c, 1, offset);
    }

}

char read_map_get(long long int block) {
    long long int offset = 32 + block/8;
    if(mem_read_map!=MAP_FAILED && offset > mem_read_map_size) {
    return 0;
    }
    char c=0;
    if(mem_read_map!=MAP_FAILED) {
    c = mem_read_map[offset];
    } else {
        pread64(fd_read_map, &c, 1, offset);
    }
    return (c & (1<<(block%8)))?1:0;
}

void read_map_set(long long int block, char val) {
    long long int offset = 32 + block/8;
    if((mem_read_map!=MAP_FAILED) && (offset > mem_read_map_size) ) {
    munmap(mem_read_map, mem_read_map_size);
    mem_read_map_size = (block/8/getpagesize()+1)*getpagesize();
    ftruncate(fd_read_map, mem_read_map_size);
    mem_read_map = mmap(NULL, mem_read_map_size , PROT_READ|PROT_WRITE, MAP_SHARED, fd_read_map, 0);
    }
    char c;
    if(mem_read_map!=MAP_FAILED) {
    c = mem_read_map[offset];
    } else {
        pread64(fd_read_map, &c, 1, offset);
    }

    char mask = 1 << (block%8);
    c &= ~mask;
    if(val) {
    c |= mask;
    }

    if(mem_read_map!=MAP_FAILED) {
    mem_read_map[offset]=c;
    } else {
        pwrite64(fd_read_map, &c, 1, offset);
    }

}

static int fusecow_getattr(const char *path, struct stat *stbuf)
{

    if(strcmp(path, "/") != 0)
        return -ENOENT;
	
	
    struct stat s_write;
    struct stat s_map;
    memset(&s_write, 0, sizeof s_write);
    memset(&s_map, 0, sizeof s_map);

    if(-1 == fstat(fd, stbuf)) {
	return -errno;
    }
    fstat(fd_write, &s_write);
    fstat(fd_write_map, &s_map);

    stbuf->st_size = st_size;
    stbuf->st_blocks = st_size/512;
    stbuf->st_blksize = block_size;
    stbuf->st_mode = 0100600;

    //stbuf->st_*time = ?
    
    return 0;
}

static int fusecow_truncate(const char *path, off64_t size)
{
    (void) size;

    if(strcmp(path, "/") != 0)
        return -ENOENT;
    

    st_size = size;
    munmap(mem_write_map, mem_write_map_size);
    mem_write_map_size = get_map_size();
    ftruncate(fd_write_map, mem_write_map_size);

    pwrite64(fd_write_map, &st_size, sizeof st_size, 8);
    
    mem_write_map = mmap(NULL, mem_write_map_size , PROT_READ|PROT_WRITE, MAP_SHARED, fd_write_map, 0);

    if(ftruncate(fd_write, size)==-1) {
	return -errno;
    }

    return 0;

}

static int fusecow_open(const char *path, struct fuse_file_info *fi)
{
    (void) fi;


    if(strcmp(path, "/") != 0)
        return -ENOENT;

    return 0;
}


static int write_read(const char *buf, size_t size,
                     off64_t offset)
{

    long long int block_number = offset / block_size;
    if(offset + size > (block_number+1)*block_size) {
    size = (block_number+1)*block_size - offset; // write only one block. read_safe will care
    }

    int res;
    if(read_map_get(block_number)) {
    res=pwrite64(fd_read, buf, size, offset);
    } else {
    int remaining = block_size;
    while(remaining) {
        res=pread64(fd, copyup_buffer + block_size - remaining, remaining, block_number*block_size);
        if(res==0) {
        memset(copyup_buffer + block_size - remaining, 0, remaining);
        break;
        }
        if(res==-1) {
        if(errno==EINTR) continue;
        return -errno;
        }
        remaining -= res;
    }

    memcpy(copyup_buffer+offset%block_size, buf, size);

    remaining=block_size;
    while(remaining) {
        fprintf(stderr, "Performing write at offset %lld\n", block_number*block_size);
        res=pwrite64(fd_read, copyup_buffer + block_size - remaining, remaining, block_number*block_size);
        if(res==-1) {
        if(errno==EINTR) continue;
        return -errno;
        }
        remaining -= res;
    }

    read_map_set(block_number, 1);

    res = size;
    }

    if (res == -1) {
        res = -errno;
    }

    return res;
}

static int fusecow_read(const char *path, char *buf, size_t size,
                     off64_t offset, struct fuse_file_info *fi)
{
    int res;

    long long int block_number = offset / block_size;
    if(offset + size > (block_number+1)*block_size) {
    size = (block_number+1)*block_size - offset; // read only one block
    }

    if(write_map_get(block_number)) {
    res=pread64(fd_write, buf, size, offset);
    } else if(read_map_get(block_number)) {
    res=pread64(fd_read, buf, size, offset);
    } else {
    res=pread64(fd, buf, size, offset);
    // Data was never read yet, write to copy-on-read file.
    if (res != write_read(buf, size, offset) && read_only)
        res = -errno;
    }

    if (res == -1)
        res = -errno;

    return res;
    
}

static int fusecow_read_safe(const char *path, char *buf, size_t size,
                     off64_t offset, struct fuse_file_info *fi)
{
    int res=0;

    if(strcmp(path, "/") != 0)
        return -ENOENT;

    size_t remaining = size;

    while(remaining) {
	int ret=fusecow_read(path, buf+res, remaining, offset+res, fi);
	if(ret==0) {
	    break;
	}
	if(ret==-1) {
	    if(errno==EINTR) continue;
	    return -errno;
	}
	res+=ret;
	remaining-=ret;
    }

    return res;
    
}

static int fusecow_write(const char *path, const char *buf, size_t size,
                     off64_t offset, struct fuse_file_info *fi)
{
    (void) fi;

    long long int block_number = offset / block_size;
    if(offset + size > (block_number+1)*block_size) {
	size = (block_number+1)*block_size - offset; // write only one block. write_safe will care
    }

    int res;
    if(write_map_get(block_number)) {
	res=pwrite64(fd_write, buf, size, offset);
    } else {
	int remaining = block_size;
	while(remaining) {
	    res=pread64(fd, copyup_buffer + block_size - remaining, remaining, block_number*block_size);
	    if(res==0) {
		memset(copyup_buffer + block_size - remaining, 0, remaining);
		break;
	    }
	    if(res==-1) {
		if(errno==EINTR) continue;
		return -errno;
	    }
	    remaining -= res;
	}

	memcpy(copyup_buffer+offset%block_size, buf, size);

	remaining=block_size;
	while(remaining) {
	    fprintf(stderr, "Performing write at offset %lld\n", block_number*block_size);
	    res=pwrite64(fd_write, copyup_buffer + block_size - remaining, remaining, block_number*block_size);
	    if(res==-1) {
		if(errno==EINTR) continue;
		return -errno;
	    }
	    remaining -= res;
	}

    write_map_set(block_number, 1);

	res = size;
    }

    if (res == -1) {
        res = -errno;
    } 

    return res;
}


static int fusecow_write_safe(const char *path, const char *buf, size_t size,
                     off64_t offset, struct fuse_file_info *fi)
{
    int res=0;
    if(strcmp(path, "/") != 0)
        return -ENOENT;

    size_t remaining = size;

    while(remaining) {
	int ret=fusecow_write(path, buf+res, remaining, offset+res, fi);
	if(ret==0) {
	    break;
	}
	if(ret==-1) {
	    if(errno==EINTR) continue;
	    return -errno;
	}
	res+=ret;
	remaining-=ret;
    }
    
    if(offset+res > st_size) {
	fprintf(stderr, "Growing files is known to fail\n");
	return -ENOSPC;
	st_size = offset+res;
    if(mem_write_map!=MAP_FAILED) {
        memcpy(mem_write_map+8, &st_size, sizeof st_size);
	} else {
        pwrite64(fd_write_map, &st_size, sizeof st_size, 8);
	}
    }

    return res;
}

static int fusecow_utimens(const char *path, const struct timespec ts[2]){

    if(strcmp(path, "/") != 0)
        return -ENOENT;

    return 0;
}       

static int fusecow_fsync(const char *path, int isdatasync,
                     struct fuse_file_info *fi)
{
    if(strcmp(path, "/") != 0)
        return -ENOENT;

    int ret=0;
    int ret1=fsync(fd_write);
    if(ret1==-1)ret=-errno;
    msync(mem_write_map, mem_write_map_size, MS_SYNC);
    int ret2=fsync(fd_write_map);
    if(ret2==-1)ret=-errno;

    return ret;
}


static struct fuse_operations fusecow_oper = {
    .getattr	= fusecow_getattr,
    .truncate	= fusecow_truncate,
    .open	= fusecow_open,
    .read	= fusecow_read_safe,
    .write	= fusecow_write_safe,   
    .utimens    = fusecow_utimens, 
    .fsync	= fusecow_fsync,
};

int main(int argc, char *argv[])
{
    int ret,i;
    char* argv2[argc-1+2];  // File name removed, "-o nonempty,direct_io" added
    int our_arguments_count=5; /* argv[0], source file, storage file and mount point */

    block_size=8192;
    fd=0;
    fd_write=0;
    fd_write_map=0;
    mem_write_map=MAP_FAILED;
    fd_read=0;
    fd_read_map=0;
    mem_read_map=MAP_FAILED;
    read_only = 0;

    int block_size_overridden=0;

    if(argc<4){
	fprintf(stderr,"fusecoraw alpha version. Copy-on-read-and-write block device using FUSE and sparse files. Fusecow originally created by _Vi, altered to fusecoraw by EvdH.\n");
    fprintf(stderr,"Usage: %s read_file mountpoint_file write_file read_file [-RM read_file.map] [-WM write_file.map] [-B blocksize] [-RO (read-only, for remounting)] [FUSE_options]\n",argv[0]);
	fprintf(stderr,"Examples:\n");
	fprintf(stderr,"    fusecoraw source mountpoint copy-on-write-fle copy-on-read-file\n");
	fprintf(stderr,"Remember to \"touch\" your mountpoints, not \"mkdir\" them.\n");
	return 1;
    }

    {
    char write_mapfile_buff[4096];
    sprintf(write_mapfile_buff, "%s.map", argv[3]);
    const char *write_mapfile = write_mapfile_buff;
    char read_mapfile_buff[4096];
    sprintf(read_mapfile_buff, "%s.map", argv[4]);
    const char *read_mapfile = read_mapfile_buff;
    for(;argv[our_arguments_count];) {
        if(!strcmp(argv[our_arguments_count], "-B")) {
        ++our_arguments_count;
        sscanf(argv[our_arguments_count], "%i", &block_size);
        block_size_overridden = 1;
        ++our_arguments_count;
        } else
        if(!strcmp(argv[our_arguments_count], "-WM")) {
        ++our_arguments_count;
        write_mapfile = argv[our_arguments_count];
        ++our_arguments_count;
        } else
        if(!strcmp(argv[our_arguments_count], "-RM")) {
        ++our_arguments_count;
        read_mapfile = argv[our_arguments_count];
        ++our_arguments_count;
        } else
        if(!strcmp(argv[our_arguments_count], "-RO")) {
        ++our_arguments_count;
        read_only = 1;
        } else {
        break;
        }
    }

    fd=open64(argv[1],O_RDONLY);
    if(fd<0){
        fprintf(stderr, "Unable to open read file \"%s\"\n", argv[1]);
        perror("open");
        return 1;
    }
    fd_write=open64(argv[3], O_RDWR|O_CREAT, 0777);
    if(fd_write<0){
        fprintf(stderr, "Unable to open write file \"%s\"\n", argv[3]);
        perror("open");
        return 1;
    }
    fd_write_map=open(write_mapfile, O_RDWR|O_CREAT, 0777);
    if(fd_write_map<0){
        fprintf(stderr, "Unable to open map file \"%s\"\n", write_mapfile);
        perror("open");
        return 1;
    }

    if(read_only)
        fd_read=open64(argv[4], O_RDONLY, 0777);
    else
        fd_read=open64(argv[4], O_RDWR|O_CREAT, 0777);
    if(fd_read<0){
        fprintf(stderr, "Unable to open read file \"%s\"\n", argv[4]);
        perror("open");
        return 1;
    }


    if(read_only)
        fd_read_map=open(read_mapfile, O_RDONLY, 0777);
    else
        fd_read_map=open(read_mapfile, O_RDWR|O_CREAT, 0777);
    if(fd_read_map<0){
        fprintf(stderr, "Unable to open read map file \"%s\"\n", read_mapfile);
        perror("open");
        return 1;
    }


    char write_signature[8];
    write_signature[0]=0;
    pread64(fd_write_map, &write_signature, sizeof write_signature, 0);
    write_signature[7]=0;
    if (strcmp(write_signature, "fusecow")) {
        // No signature:
        struct stat stbuf;
        fstat(fd, &stbuf);
        stbuf.st_size = st_size = (off64_t)lseek64(fd, (off64_t)0, SEEK_END);
        pwrite64(fd_write_map, "fusecow\n", 8, 0);
        pwrite64(fd_write_map, &st_size, sizeof st_size, 8);
        pwrite64(fd_write_map, &block_size, sizeof block_size, 16);
        // Actual data begins at offset 32
    } else {
        pread64(fd_write_map, &st_size, sizeof st_size, 8);
        int blocksize;
        pread64(fd_write_map, &blocksize, sizeof block_size, 16);
        if(block_size_overridden && blocksize!=block_size) {
        fprintf(stderr, "Your block size %d and block size %d saved in \"%s\" is not the same\nI will use saved block size anyway\n",
            block_size, blocksize, write_mapfile);
        // return 1;
        }
        block_size = blocksize;
    }

    char read_signature[8];
    read_signature[0]=0;
    pread64(fd_read_map, &read_signature, sizeof read_signature, 0);
    read_signature[7]=0;
    if (strcmp(read_signature, "fusecow")) {
        // No signature:
        struct stat stbuf;
        fstat(fd, &stbuf);
        stbuf.st_size = st_size = (off64_t)lseek64(fd, (off64_t)0, SEEK_END);
        pwrite64(fd_read_map, "fusecow\n", 8, 0);
        pwrite64(fd_read_map, &st_size, sizeof st_size, 8);
        pwrite64(fd_read_map, &block_size, sizeof block_size, 16);
        // Actual data begins at offset 32
    } else {
        pread64(fd_read_map, &st_size, sizeof st_size, 8);
        int blocksize;
        pread64(fd_read_map, &blocksize, sizeof block_size, 16);
        if(block_size_overridden && blocksize!=block_size) {
        fprintf(stderr, "Your block size %d and block size %d saved in \"%s\" is not the same\nI will use saved block size anyway\n",
            block_size, blocksize, read_mapfile);
        // return 1;
        }
        block_size = blocksize;
    }

    mem_write_map_size = get_map_size();
    ftruncate(fd_write_map, mem_write_map_size);
    mem_write_map = mmap(NULL, mem_write_map_size , PROT_READ|PROT_WRITE, MAP_SHARED, fd_write_map, 0);
    if(mem_write_map==MAP_FAILED) {
        perror("mmap");
        fprintf(stderr, "Unable to open memory mapping. Using simplified mode.\n");
    }


    mem_read_map_size = get_map_size();
    ftruncate(fd_read_map, mem_read_map_size);
    if(!read_only){
        mem_read_map = mmap(NULL, mem_read_map_size , PROT_READ|PROT_WRITE, MAP_SHARED, fd_read_map, 0);
        if(mem_read_map==MAP_FAILED) {
            perror("mmap");
            fprintf(stderr, "Unable to open memory mapping. Using simplified mode.\n");
        }
        }
    }

    copyup_buffer = (char*) malloc(block_size);

    int argc2=0;
    argv2[argc2++]=argv[0];
    argv2[argc2++]=argv[2]; // mount point file
    for(i=our_arguments_count;i<argc;++i)argv2[argc2++]=argv[i];
    argv2[argc2++]="-o";
    argv2[argc2++]="nonempty,direct_io";
    argv2[argc2]=0;

    ret=fuse_main(argc2, argv2, &fusecow_oper, NULL);

    close(fd);
    close(fd_write);
    close(fd_write_map);
    close(fd_read);
    close(fd_read_map);
    munmap(mem_write_map, mem_write_map_size);
    munmap(mem_read_map, mem_read_map_size);
    free(copyup_buffer);

    return ret;
}
