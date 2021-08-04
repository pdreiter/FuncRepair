#!/bin/bash 

#------------------------------------------------------------------
# author : pdreiter
# date   : 03/18/2021
# purpose: creates PRD infrastructure using existing tools/scripts
#------------------------------------------------------------------
dest="decomp"

mycbs=()
index=0
bin_dir=$(pwd)
src_dir=$(pwd)
funcs=()
for i in $@; do 
    echo $i
    if  [[ "$i" == "--func="* ]]; then
        funcs+=($(echo $i | sed 's/\-\-func=//'))
    elif  [[ "$i" == "--src_dir="* ]]; then
        src_dir=$(echo $i | sed 's/\-\-bin_dir=//')
    elif  [[ "$i" == "--bin_dir="* ]]; then
        bin_dir=$(echo $i | sed 's/\-\-bin_dir=//')
    elif  [[ "$i" == "--dest="* ]]; then
        dest=$(echo $i | sed 's/\-\-dest=//')
    elif [[ "$i" == "-h"  ||  "$i" == "-help"  ||  "$i" == "--help" ]]; then
        echo ""
        echo "Description: $0 [-help] [--dest=<dir>] CB"
        echo ""
        echo "This script generates a per-patched-function decompiled code for "
        echo "  specified challenge binaries: CB_i, for i=0 to N"
        echo ""
        echo "   --func=<name>    specifies the symbols to decompile for binary"
        echo "                  REQUIRED"
        echo ""
        echo "   --bin_dir=<dir>  specifies the location of the binary file"
        echo "                  default is '$bin_dir'"
        echo ""
        echo "   --src_dir=<dir>  specifies the location of build content"
        echo "                  default is '$src_dir'"
        echo ""
        echo "   --dest=<dir>     specifies the destination output directory"
        echo "                  default is '$dest'"
        echo ""
        echo "Pre-requisites: for CB:"
        echo "    1) need FuncRepair init.bash set up   => EXITS"
        echo "    2) need prd-env virtual env set up    => EXITS"
        echo "   *3) need \$CB compiled"
        echo "   *4) need genprog for \$CB set up in --src_dir"
        echo "       -- To generate, please run:"
        echo "       ./genprog_setup.bash -python3 \$CB "
        echo ""
        echo " * denotes stages that are run for you if pre-requisite files don't exist"
        echo "    if anything fails, \$CB will be SKIPPED"
        echo ""
        echo "Good Luck!"
        echo "Exiting..."
        exit 1
    else
       mycbs+=($i)
    fi
    (( index+= 1 ))
done;

if [ -z "$CGC_CB_DIR" ] || [ -z "$PRD_BASE_DIR" ]; then
    echo "Cannot continue - it looks like the CGC_CB_DIR is not set up."
    echo "This script expects PRD env to be set up, including"
    echo "  - \$CGC_CB_DIR to be set to the cb-multios-prd repo root"
    echo "  - \$PRD_(BASE|GENPROG(SRC)?)_DIR to be set"
    echo ""
    echo "This is automatically done with the FuncRepair repo's init.bash script"
    echo "Exiting..."
    exit 1;
elif [[ ! -f "$PRD_BASE_DIR/genprog_recompilation/genprog_decomp_ida.py" ]]; then
    echo "Please clone the 'genprog_recompilation' repo into $PRD_BASE_DIR"
    echo "Cannot continue, as this repo houses the decompilation scripts"
    echo "Exiting..."
    exit 1
fi

#repo_root=$(realpath ${CGC_CB_DIR})
#cd $repo_root
[[ ! -d $dest ]] && mkdir -p $dest
for i in ${mycbs[*]}; do 
    echo "Started - $i"
    if [[ ! -e "$bin_dir/$i" ]]; then
        echo "Executable for $i does not exist in $bin_dir."
        ls $bin_dir
		echo "Continuing.#"
		continue
        #pushd build32/challenges/$i > /dev/null;
        #make;
        #popd > /dev/null;
        #echo "Compiled executable for $i."
        #[[ ! -e build32/challenges/$i/$i ]] && echo "ERROR: unable to compile $i!" && continue;
    fi
    #if [[ ! -d genprog/$i ]]; then
    #    ./genprog_setup.bash -python3 -overwrite-all $i
    #elif [[ ! -h "build32/challenges/$i/poller" ]]; then
    #    ./genprog_setup.bash -python3 $i
    #fi
    neg_tests=$(grep 'neg-tests' $src_dir/configuration-func-repair | awk '{print $NF}')
    pos_tests=$(grep 'pos-tests' $src_dir/configuration-func-repair | awk '{print $NF}')

    #if (( $pos_tests==0 )) || (( $neg_tests==0 )); then 
    #    echo "valid_test_fail : $i"
    #    echo "Skipping $i - need at least 1 positive and 1 negative test [positive tests = $pos_tests; negative tests = $neg_tests]"
    #    continue;
    #fi

    #if [[ ! -e "patched_functions/${i}_info" ]]; then
    #    echo "ERROR: suspicious function list not identified for '$i'!" 
    #    echo " -- To generate, please run './tools/find_patched_functions.py $i > patched_functions/${i}_info'"
    #    echo " Please note that this rudimentary script fails with some C++ patched functions and when patch is in type or object declarations"
    #    continue;
    #fi

    #funcs=$(cat patched_functions/${i}_info | sed 's#.* : ##');
    f=$(echo ${funcs[*]} );
    x=0;
    x_list=""
    for j in $f; do 
        echo "$i,"$(realpath $bin_dir/$i)",$j" > $dest/$i.target_list.$x;
        python3 $PRD_BASE_DIR/genprog_recompilation/genprog_decomp_ida.py --target_list $dest/$i.target_list.$x --ouput_directory $dest --scriptpath $PRD_BASE_DIR/genprog_recompilation/get_ida_details.py |& tee $dest/ida.$i.$x.log;
        if [[ -e "$dest/$i" ]]; then 
            mv -v $dest/$i $dest/$i.$x
            x_list=$x_list" $x"
        else
            echo "decompilation_fail : $i.$x"
        fi
        (( x+=1 )) 
    done;
    mkdir -p $dest/$i;
    echo "$x_list"
    for x in $x_list; do
        main=0
        mv -v $dest/$i.$x $dest/$i/src.$x
        ln -sf src.$x/${i}_recomp.c $dest/$i/${i}_recomp_${x}.c
        func_stubs=$(cat $dest/$i/src.$x/${i}_funcstubs)
        func=$(echo $func_stubs | perl -p -e's/:.*$//')
        replacement=$func
        if (( $(echo $func | egrep -c '^main')>0 )); then
           echo "Patching main with patchmain"
           replacement="patchmain:main+7"
           func_stubs="patch$func_stubs"
           func="patch$func"
        fi
           
        if [[ ! -e "$dest/$i/configuration-func-repair" ]]; then 
        cp $src_dir/configuration-func-repair $dest/$i/
        fi
        perl -p -e"s/decompiled_source\./${i}_recomp_${x}\./g;" $src_dir/configuration-func-repair > $dest/$i/cfg-prd$x-
        perl -pi -e"s/^--func-repair-script.*$//;s/^--func-repair-fn-name.*$//;s/^--trampoline-compiler-opts.*$//;s/^--trampoline-linker-opts.*$//"  $dest/$i/cfg-prd$x-
        echo "--func-repair-script ./funcinsert.py --genprog --external-funcs $func_stubs " >>  $dest/$i/cfg-prd$x-
        echo "--func-repair-fn-name $replacement " >>  $dest/$i/cfg-prd$x-
        echo "--trampoline-compiler-opts -m32 -fPIC -static-pie -shared -z now -Isrc.$x" >>  $dest/$i/cfg-prd$x-
        echo "--trampoline-linker-opts -Wl,-pie,--no-dynamic-linker,--eh-frame-hdr,-z,now,-z,norelro,-T,script.ld,-static -Ilibsrc" >>  $dest/$i/cfg-prd$x-


        perl -p -e"s/decompiled_source\.c/${i}_recomp_${x}.c/g;s/^EXTERNAL_FUNCS:=.*$/EXTERNAL_FUNCS:=--external-funcs $func_stubs\n/;s/IDIRS_:=.*$/IDIRS_:=src.$x/;s/(REPLACEME:=).*$/\$1$func/;s/trampoline.bin/tramp.${x}.bin/g;s/(REPLACEMENT:=).*$/\$1$replacement/g;" $src_dir/Makefile.genprog > $dest/$i/Makefile.genprog.$x;
    done
    for k in ${i} "pov_*.pov" "test*.sh" script.ld; do 
        cp $CGC_CB_DIR/build32/challenges/$i/$k $dest/$i/;
    done;
    ln -sf $CGC_CB_DIR/tools/python3 $dest/$i/tools ;
    ln -sf $(realpath  $CGC_CB_DIR/build32/challenges/$i/poller) $dest/$i/poller;
    for x in $x_list; do
        #echo "${i},$PWD/$dest,"$(cat $dest/$i/${i}_funcstubs) > $dest/${i}/x
        #echo "python3 $PRD_BASE_DIR/genprog_recompilation/asm_fitter.py --target_list $dest/$i/x --target_directory $dest "
        #python3 $PRD_BASE_DIR/genprog_recompilation/asm_fitter.py --target_list $dest/$i/x --target_directory $dest
        if [[ -e $dest/$i/src.$x/${i}_funcstubs ]] ; then 
            func_stubs=$(cat $dest/$i/src.$x/${i}_funcstubs)
            pushd $dest/${i} > /dev/null
            make -f Makefile.genprog.$x hook
            if [[ -e libhook.so ]] ; then 
               mv libhook.so src.$x/libhook.no_asm.so
               cp src.$x/${i}_recomp.c src.$x/${i}_recomp.orig.c
               $CGC_CB_DIR/genprog_ida/create_asm.py --func $func_stubs --file-to-objdump src.$x/libhook.no_asm.so --source src.$x/${i}_recomp.c
            fi
            popd > /dev/null
        fi
    done
    echo "Completed - $i"
done;
