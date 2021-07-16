// note from PDR-
// This file was based on content from Prophet, but 
// due to the nature of BinRepared method, cannot use STL
// -- this means no vectors and no std::string types

// Copyright (C) 2016 Fan Long, Martin Rianrd and MIT CSAIL 
// Prophet
// 
// This file is part of Prophet.
// 
// Prophet is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// Prophet is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with Prophet.  If not, see <http://www.gnu.org/licenses/>.
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
//#include <cstring>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <unistd.h>
//#include <sstream>
//#include <iostream>
//#include <vector>

#define MAXSZ 1048576


//static bool init = false;
//static bool enable = false;
//static bool mutant_init = false;
//static int mutant_id = 0;
//static unsigned long current_cnt = 0;
//static unsigned long records[MAXSZ];
//static unsigned long records_sz;
 bool initialized;
 bool init;
 bool enable;
 bool mutant_init;
 int mutant_id;
 unsigned long current_cnt;
 unsigned long records[MAXSZ];
 unsigned long records_sz;
extern "C" void prophet_init();

char* _getenv(const char* name){

    if( access(name,F_OK) != -1 ){
        FILE *file=fopen(name,"r");
        char buf[255];
        char* b=fgets(buf,255,file);
        if (b!=NULL){
            int len=strlen(b)+1;
            b= (char *) malloc(len);
            strcpy(b,buf);
        }
        return b;
    }
    else { return NULL; }

}

//static void __attribute((constructor)) _init() {
void prophet_init() {
    if (initialized){ return; }
    initialized=1;
    memset(records, 0, sizeof(records));
    records_sz = 0;
    char* tmp = _getenv("IS_NEG");
    if (!tmp) return;
    //std::string is_neg = tmp;
    //if (is_neg == "") return;
    if (tmp[0]=='\0') { free(tmp); return; }
    free(tmp);
    pid_t pid = getpid();
    char link[512];
    //std::ostringstream sout;
    //sout << "/proc/" << pid << "/cmdline";
    int ret=snprintf(link,sizeof(link),"/proc/%i/cmdline",pid);
    link[ret]=0;
    //FILE *f = fopen(sout.str().c_str(), "rb");
    FILE *f = fopen(link, "rb");
    assert(f && "Cannot get the cmdline str");

    //std::vector<std::string> res;
    //res.clear();
    char c;
    //std::string now_str = "";
    char now_str[512][512];
    int i=0,j=0;
    for (i=512;i>=0;i--){ now_str[i][0]='\0';}
    i=0;
    int read_cnt = fread(&c, 1, 1, f);
    while (read_cnt == 1 && !feof(f)) {
        if (c == '\0' || c == '\n') {
            //res.push_back(now_str);
            now_str[j][i]='\0';
            j+=1;
            i=0;
        }
        else {
            now_str[j][i]=c;
            i+=1;
        }
        read_cnt = fread(&c, 1, 1, f);
    }
    fclose(f);
    int last_entry=j-1;

    // FIXME: very hacky for php, php invokes multiple times
    enable = true;
    for (unsigned long i = 0; i <= last_entry; i++) {
        //if (res[i].find("run-test") != std::string::npos) {
        if (strstr(now_str[i],"run-test") != NULL) {
            enable = false;
            break;
        }
        //if (res[i].find("echo PHP_VERSION") != std::string::npos) {
        if (strstr(now_str[i],"echo PHP_VERSION") != NULL) {
            enable = false;
            break;
        }
    }
/*    
    for (unsigned long i = 0; i < res.size(); i++) {
        if (res[i].find("run-test") != std::string::npos) {
            enable = false;
            break;
        }
        if (res[i].find("echo PHP_VERSION") != std::string::npos) {
            enable = false;
            break;
        }
    }
*/
}

bool isGoodAddr(void *pointer, size_t size) {
    int nullfd = open("/dev/random", O_WRONLY);

    if (write(nullfd, pointer, size) < 0)
    {
        close(nullfd);
        return false;
    }
    close(nullfd);

    return true;
}

extern "C" int __get_mutant() {
    if (!mutant_init) {
        char* tmp = _getenv("MUTANT_ID");
        sscanf(tmp, "%d", &mutant_id);
        mutant_init = true;
        free(tmp);
    }
    //fprintf(stderr, "running mutant: %d\n", mutant_id);
    return mutant_id;
}

#define MAGIC_NUMBER -123456789

extern "C" int __is_neg(int count, ...) {
    //fprintf(stderr, "fuck\n");
    if (!enable) return 0;
    char* is_neg = _getenv("IS_NEG");
    if (!is_neg) return 0;
    if (strcmp(is_neg, "1") == 0) {
        char* tmp = _getenv("NEG_ARG");
        if (tmp && (strcmp(tmp, "1") == 0)) {
            char* tmp_file = _getenv("TMP_FILE");
            assert(tmp_file);
            // First time here, we need to read a tmp file to know
            // where we are
            if (!init) {
                init = true;
                FILE *f = fopen(tmp_file, "r");
                if (f == NULL) {
                    records_sz = 0;
                    current_cnt = 0;
                }
                else {
                    unsigned long n;
                    int ret = fscanf(f, "%lu", &n);
                    assert( ret == 1);
                    records_sz = 0;
                    for (unsigned long i = 0; i < n; i++) {
                        unsigned long v;
                        ret = fscanf(f, "%lu", &v);
                        assert( ret == 1);
                        records[records_sz ++ ] = v;
                    }
                    unsigned long tmp;
                    ret = fscanf(f, "%lu", &tmp);
                    fclose(f);
                    if (ret != 0) {
                        assert( tmp == 0);
                        assert( records_sz > 0);
                        long long i = records_sz - 1;
                        while (i >= 0) {
                            if (records[i] == 0)
                                break;
                            else
                                i--;
                        }
                        assert( i >= 0);
                        records[i] = 1;
                        records_sz = i + 1;
                        current_cnt = 0;
                    }
                    else {
                        current_cnt = records_sz;
                    }
                }
            }
            int ret = 0;
            if (current_cnt < records_sz)
                ret = (int) records[current_cnt];
            else {
                if (records_sz < MAXSZ)
                    records[records_sz++] = 0;
            }
            current_cnt ++;

            // We write back immediate
            FILE *f = fopen(tmp_file, "w");
            assert( f != NULL );
            fprintf(f, "%lu ", records_sz);
            for (unsigned long i = 0; i < records_sz; i++) {
                fprintf(f, "%lu", records[i]);
                if (i != records_sz - 1)
                    fprintf(f, " ");
            }
            fclose(f);

            free(tmp_file);
            free(tmp);
            free(is_neg);
            return ret;
        }
        // we always return 1
        else {
            // First time here, we need to read a tmp file to know
            // where we are
            if (!init) {
                init = true;
                char* tmp_file = _getenv("TMP_FILE");
                assert(tmp_file);
                FILE* f = fopen(tmp_file, "r");
                if (f != NULL) {
                    unsigned long n, tmp;
                    int ret = fscanf(f, "%lu", &n);
                    assert(ret == 1);
                    records_sz = 0;
                    for (unsigned long i = 0; i < n; i++) {
                        ret = fscanf(f, "%lu", &records[records_sz ++]);
                        assert( ret != 0);
                    }
                    ret = fscanf(f, "%lu", &tmp);
                    fclose(f);
                    if (ret == 0) {
                        records_sz = 0;
                        current_cnt = 0;
                    }
                    else {
                        assert(tmp == 0);
                        current_cnt = records_sz;
                    }
                }
                else {
                    records_sz = 0;
                    current_cnt = 0;
                }
                free(tmp_file);
            }
            records[records_sz ++] = 1;
            current_cnt ++;

            char* tmp_file = _getenv("TMP_FILE");
            assert(tmp_file);
            // We write back immediate
            FILE *f = fopen(tmp_file, "w");
            assert( f != NULL );
            fprintf(f, "%lu ", records_sz);
            for (unsigned long i = 0; i < records_sz; i++) {
                fprintf(f, "%lu", records[i]);
                if (i != records_sz - 1)
                    fprintf(f, " ");
            }
            fclose(f);
            free(tmp_file);
            free(is_neg);
            return 1;
        }
    }
    else if (strcmp(is_neg, "0") == 0){
        free(is_neg);
        return 0;
    }
    else if ((strcmp(is_neg, "RECORD1") == 0) || (strcmp(is_neg, "RECORD0") == 0)) {
        // We print out everything into the TMP_FILE
        char* tmp_file = _getenv("TMP_FILE");
        assert(tmp_file);
        if (init == false) {
            init = true;
            FILE *f;
            records_sz = 0;
            //fprintf(stderr, "here0\n");
            if (strcmp(is_neg, "RECORD1") == 0) {
                char* neg_arg = _getenv("NEG_ARG");
                f = fopen(neg_arg, "r");
                assert(f != NULL);
                unsigned long n;

                int ret = fscanf(f, "%lu", &n);
                assert( ret == 1);
                for (unsigned long i = 0; i < n; i++) {
                    unsigned long tmp;
                    ret = fscanf(f, "%lu", &tmp);
                    assert( ret == 1);
                    records[records_sz ++] = tmp;
                }
                ret = fscanf(f, "%lu", &current_cnt);
                fclose(f);
                if (ret == 0) {
                    current_cnt = 0;
                }
                free(neg_arg);
            }
        }
        //fprintf(stderr, "here1\n");
        va_list ap;
        va_start(ap, count);
        FILE *f = fopen(tmp_file, "a");
        fprintf(f, "%lu", (unsigned long)count);
        //fprintf(stderr, "count %d cnt %lu\n", count, current_cnt);
        for (unsigned long i = 0; i < (unsigned long)count; i++) {
            void* p = va_arg(ap, void*);
            unsigned long sz = va_arg(ap, unsigned long);
            assert( sz <= 8 );
            long long v = 0;
            if (isGoodAddr(p, sz)) {
                memcpy(&v, p, sz);
            }
            else {
                v = MAGIC_NUMBER;
            }
            fprintf(f, " %lld", v);
            //fprintf(stderr, "i %lu %lld\n", i, v);
        }
        fprintf(f, "\n");
        fclose(f);
        free(tmp_file);

        if (strcmp(is_neg, "RECORD1") == 0) {
            // We write back with additional int to note the end
            char* neg_arg = _getenv("NEG_ARG");
            f = fopen(neg_arg, "w");
            assert( f != NULL );
            fprintf(f, "%lu ", records_sz);
            for (unsigned long i = 0; i < records_sz; i++) {
                fprintf(f, "%lu", records[i]);
                if (i != records_sz - 1)
                    fprintf(f, " ");
            }
            fprintf(f, "%lu", current_cnt + 1);
            fclose(f);

            assert( current_cnt < records_sz);
            //fprintf(stderr, "fuck you %lu\n", records[current_cnt]);
            free(neg_arg);
            free(is_neg);
            return records[current_cnt++];
        }
        else
            free(is_neg);
            return 0;
    }
    free(is_neg);
    return 0;
}
