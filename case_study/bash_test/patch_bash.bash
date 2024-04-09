#!/bin/bash -x

exe="/bin/bash"
baseexe=$(basename -- $exe)
myexe="my_$baseexe"
destpath=$(dirname -- $exe)
filter="builtin"
filter_name="false"

docker pull i386/ubuntu

cnt=$(docker container ls | egrep -c 'i386/ubuntu:bionic')
if (( $cnt > 0 )); then
    for i in $(docker container ls | egrep 'i386/ubuntu:bionic' | awk '{print $1}'); do
        docker rm -f $i
        sleep 1s
    done
fi

docker container ls | egrep -c 'i386/ubuntu:bionic'


docker run -id i386/ubuntu:bionic
container_id=$(docker container ls | egrep 'i386/ubuntu:bionic' | awk '{print $1}')
docker cp $container_id:$exe $myexe

if [[ ! -e $myexe ]]; then
    echo -e "Problem with docker container. Cannot get $exe from container $container_id\nExiting."
    exit -1
fi

mkdir -p decomp
status="symbol,decomp-status,recomp-status-wo-asm,recomp-status-w-asm,run-status"
# global symbols
for s in $(nm -D $myexe | egrep -w '[tT]' | egrep $filter | egrep $filter_name | awk '{print $NF}'); do 
    if [[ ! -e $myexe.$s.target_list ]]; then 
        echo "$myexe,./$myexe,$s" > $myexe.$s.target_list    
    fi
    if [[ -d ${s}_decomp ]]; then 
        rm -rf ${s}_decomp; 
    fi; 
    # specific for builtin commands
    cmd_=$(echo $s | perl -p -e"s/_?$filter//")
    decomp_stat=1
    recomp_stat=1
    recomp_stat_wasm=1
    run_stat=1
    python3.9 $PRD_BASE_DIR/partial_decompilation/prd_multidecomp_ida.py --target_list $myexe.$s.target_list \
        --decompdir ./decomp/d.$s --scriptpath $IDA_BASE_DIR --use-new-features --ouput_directory ./${s}_decomp
    decomp_stat=$?
    if [[ -e ${s}_decomp/$myexe/${myexe}_recomp.c ]] ; then    
        cp $PRD_TOOL_DIR/templates/Makefile.prd ${s}_decomp/$myexe/; 
        cp $PRD_TOOL_DIR/templates/script.ld ${s}_decomp/$myexe/; 
        cp $PRD_BASE_DIR/partial_decompilation/refs/defs.h defs.h; 
        cp $myexe ${s}_decomp/$myexe/; 
        pushd ${s}_decomp/$myexe/; 
            if [[ ! -e ${myexe}_recomp.c-orig-noasm ]]; then 
                cp ${myexe}_recomp.c ${myexe}_recomp.c-orig-noasm; 
            fi; 
            make -f Makefile.prd hook 
            if [[ -e "libhook.so" ]]; then 
                recomp_stat=0
                $PRD_TOOL_DIR/create_asm_multidetour.py --json-in prd_info.json --file-to-objdump libhook.so --source ${myexe}_recomp.c ; 
                
                make -f Makefile.prd clean hook funcinsert
                if [[ -e "${myexe}.trampoline.bin" ]]; then
                    recomp_stat_wasm=0
                    docker cp ${myexe}.trampoline.bin $container_id:$destpath/$myexe
                    # the following two docker commands need an update to containerd to work with some builds, but can manually evaluate
                    docker exec -it $container_id "$exe -c \"$cmd_ \"" > $baseexe.$cmd_.exec.log
                    docker exec -it $container_id "$myexe -c \"$cmd_ \"" > $myexe.$cmd_.exec.log
                    if (( $? == 0 )); then
                        run_stat=0
                    fi
                    
                fi
            fi
        popd; 
        if (( $recomp_stat_wasm==0 )); then 
            if [[ -e $s.prd.patch ]]; then 
                patch -F 10 < $s.prd.patch
                pushd ${s}_decomp/$myexe/;
                    make -f Makefile.prd clean hook funcinsert
                    if [[ -e "${myexe}.trampoline.bin"]]; then 
                        docker cp ${myexe}.trampoline.bin $container_id:$destpath/$myexe-patch
                    fi
                popd
            fi
        fi
    fi
    status=$status"\n$s,$decomp_stat,$recomp_stat,$recomp_stat_wasm,$run_stat"
done

echo -e $status > bash.run_status.log