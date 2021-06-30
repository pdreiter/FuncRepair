#!/usr/bin/env bash

export CC=gcc
export CXX=g++
#./build.sh
#./genpolls.sh

#--------------------------------------------------------------------------------
# script: genprog_setup.bash
# description: this script performs two distinct actions:
#         1) Generates new GenProg/APR/BinREPARED infrastructure content and initializes run directory
#     -OR-
#         2) Initializes run directory with previously built infrastructure content
#
#--------------------------------------------------------------------------------
# NOTE: You can probably run this anywhere, since I have safeguarded it with $DIR
#       which gets assigned the dirname ${BASH_SOURCE[0]} [directory of this script]
#--------------------------------------------------------------------------------
#   ./genprog_setup.bash -help
# should provide example command lines and parameter info
#
# for new CBs, recommended command line:
#   ./genprog_setup.bash -overwrite-all -v -python3 <new CB>
#
# to set up BinREPARED infrastructure for existing CBs, recommended command line:
#   ./genprog_setup.bash -all
#
#--------------------------------------------------------------------------------


DEBUG=0
DIR=$CGC_CB_DIR #$(cd "$(dirname ${BASH_SOURCE[0]})" && pwd)
SRC_DIR="${DIR}/challenges"
BUILD_DIR=$(realpath ${DIR}/build)
MYBUILD=$(basename ${BUILD_DIR})
GENPROG_DIR="${DIR}/genprog"
BUILD_GENPROG=0
BUILD_INDIVIDUAL_POS_TESTS=1
ALLCBS=0
VERBOSE=0
LIMIT=100
TESTLIST=()
PYTHON3=1
ONLY_MAKEFILE=0
help_info() {
  echo -e "\nUsage: $0 [-overwrite-all] [-python3] [-v] [-test <CB1> -test <CB2> | -all]"
  echo -e "\nCommand line Parameters:\n"
  echo -e "-overwrite-all\tOverwrites all contents in 'genprog/<CB>' subdir."
  echo -e "-python2      \tUse Python2 versions of test harness scripts [default python3]"
  echo -e "-v            \tVerbose build messages"
  echo -e "-all          \tProcess ALL CBs!! "
  echo -e "-test <NAME>  \tProcess specific CB named NAME!! (can be specified multiple times)\n"
  echo -e "In order to generate the infrastructure, a binary with the "
  echo -e "same name as the directory must exist."
  echo -e "This binary is executed against the POLL test "
  echo -e "to determine which positive test XML input results "
  echo -e "in a valid PASSing result.\n"
  echo -e "\nfor new CBs, recommended command line:"
  echo -e "   $0 -overwrite-all -v <new CB>"
  echo -e "\nto set up BinREPARED infrastructure for existing CBs, recommended command line:"
  echo -e "   $0 -all\n"
  exit
}
#(( $# > 0 )) && echo "User specified genprog input override!" && \
#  echo "This will overwrite any uncommitted changes in the 'genprog' subdirectory" && \
#  echo -e "\nPlease respond if this is what you want [Y/n]:" && \
#  read response
#[ "${response}" == "Y" ] && echo -e "\n\tOverwriting contents in 'genprog' subdir." && BUILD_GENPROG=1
[ ! -e ${GENPROG_DIR} ] && mkdir -p ${GENPROG_DIR} && BUILD_GENPROG=1
#[ ${BUILD_GENPROG} -ne 1 ] && echo -e "\n\tONLY Regenerating links for GenProg AFR use." 
args=("$@")
(( len=$# ))
(( $# > 0 )) && \
(( i = 0 ))
(( $# == 0 )) && help_info
while (( i < $len )); do  
if [[ "${args[$i]}" == "-help" || "${args[$i]}" == "-h" || "${args[$i]}" == "--help" ]]; then
    help_info
elif [[ "${args[$i]}" == "-overwrite-all" ]]; then
  BUILD_GENPROG=1 && echo "Overwriting ALL contents in 'genprog' CB subdir."; 
elif [[ "${args[$i]}" == "-all" ]]; then
ALLCBS=1 && echo "Enabling generation for all Challenge Binaries"
elif [[ "${args[$i]}" == "-python2" ]]; then
PYTHON3=0 && echo "Python2 tool runs"
elif [[ "${args[$i]}" == "-only-makefile" ]]; then
ONLY_MAKEFILE=1
elif [[ "${args[$i]}" == "-v" ]]; then
VERBOSE=1 && echo "Enabling verbose build"
elif [[ "${args[$i]}" == "-test" ]]; then
(( i+=1 )) && TESTLIST+=( ${args[$i]} ) && echo "- ${args[$i]}"
else
TESTLIST+=( ${args[$i]} ) && echo "- ${args[$i]}"
fi
(( i+=1 ))
done


build_genprog_test(){
    chal=$1
    num_pos=0
    num_pos_int=0
    num_pos_x=0
    num_neg_x=0
    num_neg=0
    index=$2
    povs=()
    CHAL=$(basename $chal)
    # G<name> <= source of link
    # L<name> <= dest of link
    GBUILD="${GENPROG_DIR}/${CHAL}"
    LBUILD="${BUILD_DIR}/challenges/${CHAL}"
    GLIBSRC="${GBUILD}/libsrc"
    LLIBSRC="${LBUILD}/libsrc"
    GTEST="${GBUILD}/test.sh"
    LTEST="${LBUILD}/test.sh"
    GGENPROG_CFG="${GBUILD}/configuration-func-repair"
    LGENPROG_CFG="${LBUILD}/configuration-func-repair"
    GMAKE="${GBUILD}/Makefile.genprog"
    LMAKE="${LBUILD}/Makefile.genprog"
    GSRC="${GBUILD}/decompiled_source.c"
    LSRC="${LBUILD}/decompiled_source.c"
    GHDR="${GBUILD}/decompiled_source.h"
    LHDR="${LBUILD}/decompiled_source.h"
    GSLD="${GBUILD}/script.ld"
    LSLD="${LBUILD}/script.ld"
    GFUNCINSERT="${PRD_BASE_DIR}/funcinsert.py"
    LFUNCINSERT="${LBUILD}/funcinsert.py"
    GFULLSRC="${SRC_DIR}/${CHAL}/src"
    LFULLSRC="${LBUILD}/src"
    GREADME="${SRC_DIR}/${CHAL}/README.md"
    LREADME="${LBUILD}/README.md"
    GFULLINC="${SRC_DIR}/${CHAL}/include"
    LFULLINC="${LBUILD}/include"
    GFULLSRCLIB="${SRC_DIR}/${CHAL}/lib"
    LFULLSRCLIB="${LBUILD}/lib"
    GTOOLDIR="${CGC_CB_DIR}/tools"
    if  [[ $PYTHON3 -eq 1 ]]; then
        GTOOLDIR="${CGC_CB_DIR}/tools/python3"
	fi
	
    LTOOLDIR="${LBUILD}/tools"
    GCHALLENGEPOLLDIR="${CGC_CB_DIR}/polls/${CHAL}"
    GPOLLDIR="${GCHALLENGEPOLLDIR}/poller"
    LPOLLDIR="${LBUILD}/poller"
    GPOLLDIR_ALTSRC="${SRC_DIR}/${CHAL}/"
    GPOLLDIR_ALT="${SRC_DIR}/${CHAL}/poller"
    # creating the compiler flags to pass into genprog and funcinsert
	SRC_LIBDIR='./lib'
    #LDIRS=( "${CGC_CB_DIR}/${MYBUILD}" )
	#DIRS=( "${CGC_CB_DIR}/build_dietlibc" "${CGC_CB_DIR}" ) 
	#IDIRS=( "include" "include/libpov" )
	#IDIRS_NOTOUCH=( "${CGC_CB_DIR}/include/libpov/pov" \
    #                "${CGC_CB_DIR}/include/libpov"  \
    #                "${CGC_CB_DIR}/include"  \
    #                "./src" )
    #STATICLIBS="${CGC_CB_DIR}/${MYBUILD}/include/libcgc-static.a ${CGC_CB_DIR}/${MYBUILD}/include/tiny-AES128-C/libtiny-AES128-C-static.a" 
	#IDIRS_=$(foreach d,\$(DIRS),\$(patsubst %, \$(d)/%,\$(IDIRS)))
    #IDIRS_=()
    #for i in ${DIRS[*]}; do for j in ${IDIRS[*]}; do IDIRS_+=( "$i/$j" ); done; done
    #echo IDIRS_ ${IDIRS_[@]} 
	#INCDIRS=""
	#INCDIRS=\$(patsubst %,-I%, \$(IDIRS_) \$(IDIRS_NOTOUCH))" >> ${GMAKE}
    #for i in ${IDIRS_NOTOUCH[*]}; do INCDIRS+="-I$i "; done
	#LIBDIRS=\$(patsubst %,-L%,\$(IDIRS_))" >> ${GMAKE}
	#LIBDIRS=""
    #for i in ${IDIRS_[*]}; do LIBDIRS+="-L$i "; done
    #GENPROG_FLAGS='-DGENPROG'
	#DEFAULT_FLAGS="${GENPROG_FLAGS} -nostartfiles -flto -z norelro -fno-builtin -w -g3 -m32 ${INCDIRS} ${LIBDIRS}"
	#LDFLAGS="-Wl,-pie,--no-dynamic-linker,--eh-frame-hdr,-z,text,-z,norelro,-T,script.ld ${STATICLIBS}"
	#CFLAGS="${DEFAULT_FLAGS} -fPIC -static-pie ${LDFLAGS} " 
    if [ -e ${LBUILD} ]; then 
        [ ! -e ${GBUILD} ] && mkdir -p ${GBUILD}
    
        echo "$DIR/challenges/$CHAL"
        cd "$DIR/challenges/$CHAL"
        if (( ${BUILD_GENPROG} > 0 )); then 
            rm -f ${LGENPROG_CFG} ${LLIBSRC} ${LTEST} ${LMAKE} ${LSRC} \
              ${LHDR} ${LFULLSRC} ${LREADME} ${LFULLINC} ${LFULLSRCLIB} \
              ${LSLD} ${LFUNCINSERT} ${LPOLLDIR} \
              ${LTOOLDIR} ${LBUILD}/genprog
            if (( $ONLY_MAKEFILE==0 )); then
                echo -e "#!/bin/bash" > ${GTEST}
    			echo -e "\n###################################################" >> ${GTEST}
    			echo -e "# THIS SCRIPT HAS BEEN AUTOMATICALLY GENERATED BY" >> ${GTEST}
    			echo -e "#          genprog_setup.bash" >> ${GTEST}
    			echo -e "###################################################\n" >> ${GTEST}
                echo -e "\n# \$1 = EXE\n# \$2 = test name\n# \$3 = port" >> ${GTEST}
                echo -e "# \$4 = source name\n# \$5 = single-fitness-file name" >> ${GTEST}
                echo -e "# exit 0 = success" >> ${GTEST}
                echo -e "bin=\$1\ntst=\$2\n#trap 'kill \$(jobs -p)' EXIT" >> ${GTEST}
                echo -e "#exe=\"setarch \$(uname -m) -R \$bin\"" >> ${GTEST} 
                echo -e "\nexport LD_BIND_NOW=1\n" >> ${GTEST} 
                echo -e "\ncase \$tst in\n" >> ${GTEST}
                if (( ${BUILD_INDIVIDUAL_POS_TESTS} > 0 )); then
                    polldir=""
                    echo "POLLER => $DIR/challenges/$CHAL/poller"
                    pdirs=$(ls -d ./poller/*)
                    echo "pdirs=>${pdirs[*]}"
                    for polldir in ${pdirs[*]}; do
                        (( num_pos = num_pos_int ))
                        num_pos_int=0
                        #ls $polldir
                        if [[ -e "$polldir/machine.py" || -e "$polldir/GEN_00000_00001.xml" || -e "$polldir/POLL_00001.xml" ]]; then
                            #echo "rm -f ${LPOLLDIR}"
                            POLLDEST=${LPOLLDIR}
                            echo "POLLDEST=$POLLDEST"
                            if [[ -e ${GPOLLDIR} ]]; then
                                ln -nsf ${GPOLLDIR} ${POLLDEST}
                            else
                                if [[ ! -e "${POLLDEST}" ]]; then
                                ln -nsf ${GPOLLDIR_ALT} ${POLLDEST}
                                else
                                   ln -nsf ${GPOLLDIR_ALTSRC}/$polldir ${POLLDEST}
                                fi
                            fi
                            #ls -ld $LPOLLDIR/*
    
                            #OUTDIR="$DIR/polls/$CHAL/$polldir"
                            #DSTDIR="${LBUILD}"
                            #ln -sf $OUTDIR $DSTDIR
                            #mkdir -p "$OUTDIR"
                            #/usr/bin/env python2 -B $DIR/tools/generate-polls/generate-polls --count 100 --store_seed --depth 1048575 "$polldir/machine.py" "$polldir/state-graph.yaml" "$OUTDIR"
                            #poll_count=100
                            # We are only going to generate test cases for the passing test cases with the original challenge binary
                            echo -e "Running positive tests on ${CHAL}"
                            prefix=""
                            echo "${chal_build}/$polldir/GEN_00000_00001.xml" 
                            if [[ -e "${chal_build}/$polldir/GEN_00000_00001.xml" ]]; then 
                                echo "GEN"
                                prefix="GEN_00000"
                            elif [[ -e "${chal_build}/$polldir/POLL_00001.xml" ]]; then 
                                echo "POLL"
                                prefix="POLL"
                            fi
                            echo "PREFIX => $prefix"
                            if [[ $prefix == "" ]]; then 
                                echo "No generated XML in $polldir"
                                continue
                            fi
                            first=$(ls ${chal_build}/$polldir/${prefix}_*.xml | sort -u | head -n1 | perl -p -e "s/^.*${prefix}_//;s/\.xml//;s/^0{0,4}//g")
                            last=$(ls ${chal_build}/$polldir/${prefix}_*.xml | sort -ur | head -n1 | perl -p -e "s/^.*${prefix}_//;s/\.xml//;s/^0{0,4}//g")
    
                            echo "polldir = $polldir"
                            echo "PREFIX = $prefix"
                            echo "first = $first"
                            echo "last = $last"
                            if (( $last > $LIMIT )); then 
                                echo -e "More than 100 tests are in this test suite!"
                                echo -e "Only generating test run with first 100 passing tests\n"
                            fi
                            #for x in $(seq -f "%05g" $first $LIMIT ); do
                            i=$first
                            while (( $num_pos_int <= $LIMIT )); do
                                x=$(printf "%05g" $i)
                                #echo -n "INDEX $i, $x"
                                chal_build="${LBUILD}"
                                pass=1
                                if [[ -e "${chal_build}/$polldir/${prefix}_${x}.xml" ]]; then 
                                pushd ${chal_build} > /dev/null
                                echo -n "$x, "
                                pass=0
                                if  [[ $DEBUG -ne 1 ]]; then
                                #scriptout=$(python2 ${CGC_CB_DIR}/tools/cb-replay.py --cbs $CHAL --timeout 5 --negotiate $polldir/${prefix}_${x}.xml)
                                #scriptout=$(python2 ./tools/cb-replay.py --cbs $CHAL --timeout 5 --negotiate $polldir/${prefix}_${x}.xml)
                                scriptout=$($GTOOLDIR/cb-replay.py --cbs $CHAL --timeout 5 --negotiate $polldir/${prefix}_${x}.xml > /dev/null)
                                pass=$?
                                fi
                                popd > /dev/null
                                fi
                                if (( $pass == 0 )); then 
                                    (( num_pos_int += 1 ))
                                    (( num_pos_x=num_pos+num_pos_int ))
                                    echo -e "p$num_pos_x)" >> ${GTEST}
                                    #echo -e "\tpython2 ${CGC_CB_DIR}/tools/cb-replay.py --cbs \$bin --timeout 5 --negotiate $polldir/${prefix}_${x}.xml" >> ${GTEST}
                                    echo -e "\t./tools/cb-replay.py --cbs \$bin --timeout 5 --negotiate $polldir/${prefix}_${x}.xml" >> ${GTEST}
                                    echo -e ";;" >> ${GTEST}
                                    echo "num_pos_x => $num_pos_x"
                                fi 
                                (( i+=1 ))
                                if (( $i > $last )); then
                                    break;
                                fi
                            done
                        fi
                    done
                    (( num_pos=num_pos_x ))
                else
                    # now Positive Tests
                    # Updating to modified tester.py which fails fast for positive tests with --genprog
                    #    and testing binary \$bin
                    (( num_pos += 1 ))
                    echo -e "p$num_pos)" >> ${GTEST}
                    #echo -e "\tpython2 ${CGC_CB_DIR}/tools/tester.py -c ${CHAL} --polls --genprog --gpbin \$bin " >> ${GTEST}
                    echo -e "\t ./tools/tester.py -c ${CHAL} --polls --genprog --gpbin \$bin " >> ${GTEST}
                    echo -e ";;" >> ${GTEST}
                    #/usr/bin/python2 /home/bss-lab-1/FunctionRepair/FuncRepair/cgc/cb-multios/tools/cb-replay-pov.py --debug --cbs ./Accel --timeout 5 --negotiate ./pov_2.pov
                fi
                echo -e "#n1)" >> ${GTEST}
                #echo -e "\t#python2 ${CGC_BASE_DIR}/cb-multios/tools/cb-test.py --cb \$bin --timeout 5 --negotiate --directory ./ --xml_dir ./ --concurrent 4" >> ${GTEST}
                echo -e "\t#./tools/cb-test.py --cb \$bin --timeout 5 --negotiate --directory ./ --xml_dir ./ --concurrent 4" >> ${GTEST}
                echo -e "#;;" >> ${GTEST}
                # now Negative Tests
                povs=()
				neg_list=()
				cp ${GTEST} ${GTEST}.tmp
                for i in ${LBUILD}/pov*; do
                    pov=$(basename $i)
                    scriptout=$($GTOOLDIR/cb-replay-pov.py --cbs ${LBUILD}/$CHAL --timeout 5 --negotiate ${LBUILD}/${pov} > /dev/null)
                    pass=$?
                    if (( $pass != 0 )); then 
                    s=$(echo $pov | sed 's/\..*//')
                    povs+=($s)
                    sTEST=${GBUILD}/test-$s.sh
                    cp ${GTEST}.tmp ${sTEST}
                    (( num_neg += 1 ))
                    echo -e "n1)" >> ${sTEST}
                    echo -e "n${num_neg})" >> ${GTEST}
                    #echo -e "\tpython2 ${CGC_BASE_DIR}/cb-multios/tools/cb-replay-pov-popen.py --cbs \$bin --timeout 5 --negotiate ${pov}" >> ${GTEST}
                    echo -e "\t./tools/cb-replay-pov.py --cbs \$bin --timeout 5 --negotiate ${pov}\n;;\nesac\n\nexit \$?" >> ${sTEST}
                    echo -e "\t./tools/cb-replay-pov.py --cbs \$bin --timeout 5 --negotiate ${pov}\n" >> ${GTEST}
                    echo -e ";;\n" >> ${GTEST}
    				fi
                done
				rm ${GTEST}.tmp
                echo -e "esac" >> ${GTEST}
                echo -e "\nexit \$?" >> ${GTEST}
    
                echo -e "--seed 0" > ${GGENPROG_CFG}
                echo -e "--disable-aslr" >> ${GGENPROG_CFG}
                echo -e "--program decompiled_source.i" >> ${GGENPROG_CFG}
                echo -e "--search ga" >> ${GGENPROG_CFG}
                echo -e "--popsize 40" >> ${GGENPROG_CFG}
                echo -e "--generations 10" >> ${GGENPROG_CFG}
                echo -e "--compiler ${CC}" >> ${GGENPROG_CFG}
                echo -e "--func-repair" >> ${GGENPROG_CFG}
                echo -e "--func-repair-binary ./${CHAL}" >> ${GGENPROG_CFG}
                echo -e "--func-repair-fn-name CHANGEME" >> ${GGENPROG_CFG}
                echo -e "--do-not-instrument CHANGEME" >> ${GGENPROG_CFG}
                echo -e "--func-repair-insert decompiled_source.c" >> ${GGENPROG_CFG}
                echo -e "--trampoline-compiler-opts ${CFLAGS}" >> ${GGENPROG_CFG}
                [ "${CC}" == "clang" ] && echo -e "--trampoline-nodietlibc" >> ${GGENPROG_CFG}
                #echo -e "--fault-scheme uniform" >> ${GGENPROG_CFG}
                #echo -e "--fix-scheme uniform" >> ${GGENPROG_CFG}
                echo -e "--minimization" >> ${GGENPROG_CFG}
                echo -e "--edit-script" >> ${GGENPROG_CFG}
                echo -e "--func-repair-script ./funcinsert.py --genprog" >> ${GGENPROG_CFG}
                echo -e "--blacklist-src-functions main" >> ${GGENPROG_CFG}
                echo -e "--pos-tests ${num_pos}" >> ${GGENPROG_CFG}
                for i in ${povs[*]}; do
                    s=${GBUILD}/configuration-func-repair-$i;
                    cp ${GGENPROG_CFG} $s;
                    echo "--neg-tests 1" >> $s;
                    echo "--test-script ./test-$i.sh" >> $s;
                done
                echo -e "--neg-tests ${num_neg}" >> ${GGENPROG_CFG}
	        else
			    num_neg=$(cat $GGENPROG_CFG | egrep '\-\-neg\-tests' | awk '{print $NF}')
			    num_pos=$(cat $GGENPROG_CFG | egrep '\-\-pos\-tests' | awk '{print $NF}')
				povs=$(ls $GBUILD/test-pov*.sh | perl -pi "s/$GBUILD\/test-//g;s/\.sh//")
            fi
			echo -e "\n###########################################" > ${GMAKE}
			echo -e "# THIS SCRIPT HAS BEEN AUTOMATICALLY GENERATED BY" >> ${GMAKE}
			echo -e "#          genprog_setup.bash" >> ${GMAKE}
			echo -e "###########################################\n" >> ${GMAKE}
            echo -e "SHELL:=/bin/bash\n" >> ${GMAKE}
            echo -e "\nBIN:=${CHAL}\n" >> ${GMAKE}
            echo -e "MYSRC:=decompiled_source.c" >> ${GMAKE}
            echo -e "MYREP:=repair.c" >> ${GMAKE}
            echo -e "MYOBJ:=\$(patsubst %.c,%.o, \$(MYSRC))" >> ${GMAKE}
            echo -e "MYINT:=\$(patsubst %.c,%.i, \$(MYSRC))\n" >> ${GMAKE}
            echo -e "REPLACEME:=CHANGEME" >> ${GMAKE}
            echo -e "REPLACEMENT:=\$(REPLACEME)" >> ${GMAKE}
            echo -e "#EXTERNAL_FUNCS:=--external-funcs \$(REPLACEME):cgc_calloc,cgc_malloc,cgc_free,cgc_realloc" >> ${GMAKE}
            echo -e "EXTERNAL_FUNCS:=" >> ${GMAKE}
            echo -e "\n#external scripts/tools" >> ${GMAKE}
            echo -e "ifeq (\${PRD_BASE_DIR},)" >> ${GMAKE}
            echo -e "FUNCREP:=\"./funcinsert.py\"" >> ${GMAKE}
            echo -e "else" >> ${GMAKE}
            echo -e "FUNCREP:=\"\${PRD_BASE_DIR}/funcinsert.py\"" >> ${GMAKE}
            echo -e "endif" >> ${GMAKE}
            echo -e "DIET_GCC:=\${DIET32PATH}/diet_gcc" >> ${GMAKE}
            echo -e "\n#some prophet-related overhead" >> ${GMAKE}
            echo -e "override:=0" >> ${GMAKE}
            echo -e "ORIG_CC:=\$(CC)" >> ${GMAKE}
            echo -e "ifeq (\$(CC),gcc)" >> ${GMAKE}
            echo -e "override:=1" >> ${GMAKE}
            echo -e "endif" >> ${GMAKE}
            echo -e "ifeq (\$(CC),cc)" >> ${GMAKE}
            echo -e "override:=1" >> ${GMAKE}
            echo -e "endif" >> ${GMAKE}
            echo -e "ifeq (\$(override),1)" >> ${GMAKE}
            echo -e "CC:=gcc" >> ${GMAKE}
            echo -e "CFLAGS:= \$(CFLAGS) -nodefaultlibs -fno-stack-protector" >> ${GMAKE}
            echo -e "endif" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "ifneq (\${NODIET},)\n\tCOMPILE ?= \$(CC) \$(CFLAGS)" >> ${GMAKE}
            echo -e "else \n\tCOMPILE := \$(DIET_GCC) " >> ${GMAKE}
            echo -e "endif" >> ${GMAKE}
            echo -e "#end of prophet-related overhead" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "# directories" >> ${GMAKE}
            echo -e "TMPDIR:=tmp" >> ${GMAKE}
            echo -e "OBJDIR:=depobj" >> ${GMAKE}
            echo -e "LIBSRC:=libsrc" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "# expansive Make terms" >> ${GMAKE}
            echo -e "DEPS:=\$(wildcard \$(LIBSRC)/*.[csS]) " >> ${GMAKE}
            echo -e "IDIRS_:=\$(LIBSRC)" >> ${GMAKE}
            echo -e "INCDIRS:=\$(patsubst %,-I%, \$(IDIRS_))" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "# compilation flags" >> ${GMAKE}
            echo -e "GENPROG_FLAGS:=-DGENPROG -DCGC_32BIT -DCGC_GCC -DCGC_GCC_32BIT -DLINUX " >> ${GMAKE}
            echo -e "DEFAULT_FLAGS:=\$(GENPROG_FLAGS) -m32 -fPIC -static-pie -shared -z now " >> ${GMAKE}
            echo -e "LDFLAGS:=-Wl,-pie,--no-dynamic-linker,--eh-frame-hdr,-z,now,-z,norelro,-T,script.ld,-static" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "REPDEP_OBJS:=\$(patsubst %.c, \$(OBJDIR)/%.o, \$(patsubst \$(LIBSRC)/%.c, \$(OBJDIR)/%.o, \$(DEPS) \$(MYREP)))" >> ${GMAKE}
            echo -e "DEP_OBJS:=\$(patsubst %.c, \$(OBJDIR)/%.o, \$(patsubst \$(LIBSRC)/%.c, \$(OBJDIR)/%.o, \$(DEPS) \$(MYSRC)))" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "GENPROG_TMP := \$(patsubst \$(LIBSRC)/%.c, \$(TMPDIR)/%.i, \$(DEPS))" >> ${GMAKE}
            echo -e "\nall: hook funcinsert\n" >> ${GMAKE}
            echo -e "\n\$(MYSRC):" >> ${GMAKE}
            echo -e "\t@touch \$(MYSRC)" >> ${GMAKE}
            echo -e "\t@rm -f \$(OBJDIR)/\$(MYOBJ)" >> ${GMAKE}
            echo -e "\t@rm -f \$(MYINT)" >> ${GMAKE}
            echo -e "\n.PHONY: \$(MYSRC) repair" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "\$(OBJDIR)/\$(MYOBJ): \$(MYSRC) \$(DEP_OBJS)" >> ${GMAKE}
            echo -e "\t@mkdir -p \$(OBJDIR)" >> ${GMAKE}
            echo -e "\t@mkdir -p \$(TMPDIR)" >> ${GMAKE}
            echo -e "\t\$(COMPILE) \$(DEFAULT_FLAGS) --save-temps -c \$< -o \$@  \$(INCDIRS)" >> ${GMAKE}
            echo -e "\t@\$(shell [[ -f \"*.[os]\" ]] && mv *.[os] \$(TMPDIR)/ )" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "\$(OBJDIR)/%.o: \$(LIBSRC)/%.c " >> ${GMAKE}
            echo -e "\t@mkdir -p \$(OBJDIR)" >> ${GMAKE}
            echo -e "\t@mkdir -p \$(TMPDIR)" >> ${GMAKE}
            echo -e "\t\$(COMPILE) \$(DEFAULT_FLAGS) --save-temps -c \$< -o \$@  \$(INCDIRS)" >> ${GMAKE}
            echo -e "\t@\$(shell [[ -f \"*.[ios]\" ]] && mv *.[ios] \$(TMPDIR)/ )" >> ${GMAKE}
            echo -e "\t#mv *.res \$(TMPDIR)/" >> ${GMAKE}
            echo -e "\t#mv *.out \$(TMPDIR)/" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "hook: \$(OBJDIR)/\$(MYOBJ) " >> ${GMAKE}
            echo -e "\t@echo \$(DEP_OBJS)" >> ${GMAKE}
            echo -e "\t\$(COMPILE) \$(DEFAULT_FLAGS) -o libhook.so \$(DEP_OBJS) \$(LDFLAGS) \$(INCDIRS)" >> ${GMAKE}
            echo -e "\t@\$(COMPILE) \$(DEFAULT_FLAGS) -o check \$(DEP_OBJS) \$(INCDIRS) " >> ${GMAKE}
			echo -e "\t@echo -e \"\\\nChecking for unbound functions or variables => U <func>\"" >> ${GMAKE}
			echo -e "\t@nm check | (egrep -w 'U'; [[ \"\$\$?\" -ne \"0\" ]] || (echo \"Error! Unbound functions!\" && rm check && /bin/false))" >> ${GMAKE}
			echo -e "\t@rm check && echo -e \" => SUCCESS! NO Unbound Functions\\\n\"" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "genprog_cmd:" >> ${GMAKE}
            echo -e "\t@echo --func-repair-script \$(FUNCREP) --genprog \$(EXTERNAL_FUNCS)" >> ${GMAKE}
            echo -e "\t@echo --trampoline-compiler-opts \$(DEFAULT_FLAGS) \$(GENPROG_TMP) \$(INCDIRS) " >> ${GMAKE}
            echo -e "\t@echo --trampoline-linker-opts \$(LDFLAGS) \$(INCDIRS)" >> ${GMAKE}
            echo -e "\t@echo --func-repair-fn-name \$(REPLACEMENT)" >> ${GMAKE}
            echo -e "\t@echo --func-repair-insert \$(MYSRC)" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "all_c: hook" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "funcinsert: hook" >> ${GMAKE}
            echo -e "\t\$(FUNCREP) --do-not-override-so --bin \$(BIN) --outbin \$(BIN).trampoline.bin --fn \$(MYSRC) \$(REPLACEMENT) \$(EXTERNAL_FUNCS)" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "repair:" >> ${GMAKE}
            echo -e "\t\$(COMPILE) \$(DEFAULT_FLAGS) --save-temps -c \$(MYREP) -o \$(OBJDIR)/repair.o  \$(INCDIRS)" >> ${GMAKE}
            echo -e "\t\$(COMPILE) \$(DEFAULT_FLAGS) -o libhook.so \$(REPDEP_OBJS) \$(LDFLAGS) \$(INCDIRS)" >> ${GMAKE}
            echo -e "\t@\$(COMPILE) \$(DEFAULT_FLAGS) -o check \$(REPDEP_OBJS) \$(INCDIRS)" >> ${GMAKE}
			echo -e "\t@echo -e \"\\\nChecking for unbound functions or variables => U <func>\"" >> ${GMAKE}
			echo -e "\t@nm check | (egrep -w 'U'; [[ \"\$\$?\" -ne \"0\" ]] || (echo \"Error! Unbound functions!\" && rm check && /bin/false))" >> ${GMAKE}
			echo -e "\t@rm check && echo -e \" => SUCCESS! NO Unbound Functions\\\n\"" >> ${GMAKE}
            echo -e "\t\$(FUNCREP) --do-not-override-so --bin \$(BIN) --outbin \$(BIN).repaired --fn \$(MYREP) \$(REPLACEMENT) \$(EXTERNAL_FUNCS)" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "clean_genprog:" >> ${GMAKE}
            echo -e "\trm -f repair.* *.cache coverage.*" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "clean_temp:\n\trm -rf \$(TMPDIR) \$(OBJDIR)\n" >> ${GMAKE}
            echo -e "clean_hook: clean_temp" >> ${GMAKE}
            echo -e "\trm -f decompiled_source.[ios] decompiled_source.bc libhook.o" >> ${GMAKE}
            echo -e "\trm -rf \$(TMPDIR) \$(OBJDIR)" >> ${GMAKE}
            echo -e "" >> ${GMAKE}
            echo -e "clean: clean_genprog clean_hook" >> ${GMAKE}

            if (( $ONLY_MAKEFILE==0 )); then
    
                # GENERATING THE DECOMPILED SOURCE CODE FILE
    			echo -e "//############################################" > ${GSRC}
    			echo -e "// THIS FILE HAS BEEN AUTOMATICALLY GENERATED BY" >> ${GSRC}
    			echo -e "//          genprog_setup.bash" >> ${GSRC}
    			echo -e "//##########################################\n" >> ${GSRC}
    			echo -e "#include \"decompiled_source.h\"\n" >> ${GSRC}
    			echo -e "\n\n//  Please populate with vulnerable code segments\n" >> ${GSRC}
                echo -e "// Otherwise, the following can be used as a template:" >> ${GSRC}
                echo -e "#ifdef PARAMS_NEEDED" >> ${GSRC}
                echo -e "typedef void* (*pcgc_calloc)(cgc_size_t,cgc_size_t);" >> ${GSRC}
                echo -e "pcgc_calloc cgc_calloc = NULL;" >> ${GSRC}
                echo -e "typedef void* (*pcgc_malloc)(cgc_size_t);" >> ${GSRC}
                echo -e "pcgc_malloc cgc_malloc = NULL;" >> ${GSRC}
                echo -e "typedef void (*pcgc_free)(void*);" >> ${GSRC}
                echo -e "pcgc_free cgc_free = NULL;" >> ${GSRC}
                echo -e "typedef void* (*pcgc_realloc)(void*,cgc_size_t);" >> ${GSRC}
                echo -e "pcgc_realloc cgc_realloc = NULL;" >> ${GSRC}
                echo -e "#endif\n\n" >> ${GSRC}
                echo -e "void CHANGEME(" >> ${GSRC}
                echo -e "#ifdef PARAMS_NEEDED" >> ${GSRC}
                echo -e "void* mycgc_calloc," >> ${GSRC}
                echo -e "void* mycgc_malloc, " >> ${GSRC}
                echo -e "void* mycgc_free, " >> ${GSRC}
                echo -e "void* mycgc_realloc" >> ${GSRC}
                echo -e "#endif" >> ${GSRC}
                echo -e "//, remaining params" >> ${GSRC}
                echo -e ") " >> ${GSRC}
                echo -e "{" >> ${GSRC}
                echo -e "#ifdef PARAMS_NEEDED" >> ${GSRC}
                echo -e "    cgc_calloc = (pcgc_calloc) mycgc_calloc;" >> ${GSRC}
                echo -e "    cgc_malloc = (pcgc_malloc) mycgc_malloc;" >> ${GSRC}
                echo -e "    cgc_free = (pcgc_free) mycgc_free;" >> ${GSRC}
                echo -e "    cgc_realloc = (pcgc_realloc) mycgc_realloc;" >> ${GSRC}
                echo -e "    //void x = " >> ${GSRC}
                echo -e "    myCHANGEME(" >> ${GSRC}
                echo -e "    // remaining params" >> ${GSRC}
                echo -e "    );" >> ${GSRC}
                echo -e "    //------------------------------------------------------------" >> ${GSRC}
                echo -e "    // IMPORTANT NOTES TO PATCH DEVELOPER" >> ${GSRC}
                echo -e "    // To ensure C Calling Convention Consistency between the detour insertion" >> ${GSRC}
                echo -e "    //  (this is the JMP/E9 inserted in original function)" >> ${GSRC}
                echo -e "    //  and the original function caller" >> ${GSRC}
                echo -e "    //   == THIS MUST BE UPDATED CORRECTLY ==" >> ${GSRC}
                echo -e "    // 1) If the number of void* being passed in changes," >> ${GSRC}
                echo -e "    //    Update the following line for the correct value, s.t. " >> ${GSRC}
                echo -e "    //     => add \$0x10,%esp" >> ${GSRC}
                echo -e "    //     \$0x10 = 4 void pointers * 4 BYTES" >> ${GSRC}
                echo -e "    // 2) Check how much the stack changed in this function call:" >> ${GSRC}
                echo -e "    //    What effects the stack growth: local variables " >> ${GSRC}
                echo -e "    //      a)  local variables " >> ${GSRC}
                echo -e "    //      b)  parameters for myCHANGEME function call " >> ${GSRC}
                echo -e "    //     => add \$0x8,%esp" >> ${GSRC}
    
                echo -e "    //    Q:How can you check what this value should be?" >> ${GSRC}
                echo -e "    //    A: Just compile this file and look at the objdump" >> ${GSRC}
                echo -e "    //       The %esp will be reduced as items are pushed or copied onto the stack" >> ${GSRC}
                echo -e "    //       Before returning, %esp will be increased" >> ${GSRC}
                echo -e "    //       This is the value you need to replace \$0x8 with." >> ${GSRC}
                echo -e "    //------------------------------------------------------------" >> ${GSRC}
                echo    "    asm (" >> ${GSRC}
                echo    "    \"nop\n\t\"" >> ${GSRC}
                echo    "    \"nop\n\t\"" >> ${GSRC}
                echo    "    \"nop\n\t\"" >> ${GSRC}
                echo    "    \"nop\n\t\"" >> ${GSRC}
                echo    "    \"add \$0x4,%esp\n\t\"" >> ${GSRC}
                echo    "    \"pop %ebx\n\t\"" >> ${GSRC}
                echo    "    \"pop %ebp\n\t\"" >> ${GSRC}
                echo    "    \"pop %ecx\n\t\"" >> ${GSRC}
                echo    "    \"add \$0x10,%esp\n\t\"" >> ${GSRC}
                echo    "    \"push %ecx\n\t\"" >> ${GSRC}
                #echo    "    \"leave\n\t\"" >> ${GSRC}
                echo    "    \"ret\n\t\"" >> ${GSRC}
                echo    "    );" >> ${GSRC}
                echo -e "    myreturn:" >> ${GSRC}
                echo -e "    //return x;" >> ${GSRC}
                echo -e "    return;" >> ${GSRC}
                echo -e "#else" >> ${GSRC}
                echo -e "    return myCHANGEME(" >> ${GSRC}
                echo -e "    // remaining params" >> ${GSRC}
                echo -e "    );" >> ${GSRC}
                echo -e "#endif" >> ${GSRC}
                echo -e "}" >> ${GSRC}
                echo -e " " >> ${GSRC}
    			echo -e "\nvoid myCHANGEME(\n)\n{ \n\n\n\n}\n" >> ${GSRC}
    			echo -e "\nvoid main()\n{" >> ${GSRC}
                echo -e "\tCHANGEME(" >> ${GSRC}
                echo -e "#ifdef PARAMS_NEEDED" >> ${GSRC}
                echo -e "\t\tNULL," >> ${GSRC}
                echo -e "\t\tNULL," >> ${GSRC}
                echo -e "\t\tNULL," >> ${GSRC}
                echo -e "\t\tNULL" >> ${GSRC}
                echo -e "#endif" >> ${GSRC}
                echo -e "\t\t// remaining params" >> ${GSRC}
                echo -e "\t);" >> ${GSRC}
                echo -e "}\n" >> ${GSRC}
                # GENERATING THE DECOMPILED SOURCE CODE HEADER
    			echo -e "#ifndef DECOMPILED_SOURCE_HEADER_FILE" > ${GHDR}
    			echo -e "#define DECOMPILED_SOURCE_HEADER_FILE" >> ${GHDR}
    			echo -e "//############################################" >> ${GHDR}
    			echo -e "// THIS FILE HAS BEEN AUTOMATICALLY GENERATED BY" >> ${GHDR}
    			echo -e "//          genprog_setup.bash" >> ${GHDR}
    			echo -e "//##########################################\n" >> ${GHDR}
    			echo -e "\n\n//  Please populate with vulnerable code segments\n" >> ${GHDR}
    			echo -e "\nvoid myCHANGEME(\n);\n" >> ${GHDR}
                echo -e "void CHANGEME(" >> ${GHDR}
                echo -e "#ifdef PARAMS_NEEDED" >> ${GHDR}
                echo -e "void* mycgc_calloc," >> ${GHDR}
                echo -e "void* mycgc_malloc, " >> ${GHDR}
                echo -e "void* mycgc_free, " >> ${GHDR}
                echo -e "void* mycgc_realloc," >> ${GHDR}
                echo -e "#endif" >> ${GHDR}
                echo -e "//, remaining params" >> ${GHDR}
                echo -e ");" >> ${GHDR}
    			echo -e "\n\n\n#endif" >> ${GHDR}
    
    			echo -e "PHDRS" > ${GSLD}
    			echo -e "{" >> ${GSLD}
    			echo -e "\theaders PT_PHDR PHDRS ;" >> ${GSLD}
    			echo -e "\tinterp PT_INTERP ;" >> ${GSLD}
    			echo -e "\ttext PT_LOAD FILEHDR PHDRS;" >> ${GSLD}
    			echo -e "\tdata PT_LOAD ;" >> ${GSLD}
    			echo -e "\tdynamic PT_DYNAMIC ;" >> ${GSLD}
    			echo -e "}" >> ${GSLD}
    			echo -e "" >> ${GSLD}
    			echo -e "SECTIONS" >> ${GSLD}
    			echo -e "{" >> ${GSLD}
    			echo -e "\t. = SIZEOF_HEADERS;" >> ${GSLD}
    			echo -e "\t.rela.plt : { *(.rela.plt) } :text" >> ${GSLD}
    			echo -e "\t.plt : { *(.plt) } :text" >> ${GSLD}
    			echo -e "\t.plt.got : { *(.plt.got) } :text" >> ${GSLD}
    			echo -e "\t.text : { *(.text) } :text" >> ${GSLD}
    			echo -e "\t.data : { *(.data) } :text" >> ${GSLD}
    			echo -e "\t.rodata : { *(.rodata) } :text" >> ${GSLD}
    			echo -e "\t.bss : { *(.bss) } :text" >> ${GSLD}
    			echo -e "\t.dynamic : { *(.dynamic) } :text" >> ${GSLD}
    			echo -e "}" >> ${GSLD}
            fi
        fi
        # let's link the genprog elements to the build directory
        rm -f ${LGENPROG_CFG} ${LLIBSRC} ${LTEST} ${LMAKE} ${LSRC} \
              ${LHDR} ${LFULLSRC} ${LREADME} ${LFULLINC} ${LFULLSRCLIB} \
			  ${LTOOLDIR} \
			  ${LPOLLDIR} \
              ${LSLD} ${LFUNCINSERT} \ #${LPOLLDIR} \
              ${LBUILD}/genprog

        [ ! -e ${GLIBSRC} ] && mkdir -p ${GLIBSRC}
        [ -e ${GFULLINC} ] && ln -sf ${GFULLINC} ${LFULLINC}
        ln -sf ${GTOOLDIR} ${LTOOLDIR}
        ln -sf ${GREADME} ${LREADME}
        ln -sf ${GLIBSRC} ${LLIBSRC}
        ln -sf ${GGENPROG_CFG} ${LGENPROG_CFG}
        ln -sf ${GTEST} ${LTEST}
        ln -sf ${GMAKE} ${LMAKE}
        ln -sf ${GSRC} ${LSRC}
        ln -sf ${GHDR} ${LHDR}
        ln -sf ${GFULLSRC} ${LFULLSRC}
        ln -sf ${GFULLSRCLIB} ${LFULLSRCLIB}
        ln -sf ${GSLD} ${LSLD}
        ln -sf ${GFUNCINSERT} ${LFUNCINSERT}
        #if [ ${BUILD_GENPROG} -ne 1 ] ; then 
                        POLLDEST=${LPOLLDIR}
                        if [[ ! -e "${POLLDEST}" ]]; then
                            if [[ -e ${GPOLLDIR} ]]; then
                                ln -nsf ${GPOLLDIR} ${POLLDEST}
                                for x in $(ls -d ${GPOLLDIR_ALT}/for*); do 
                                   if [[ -e "$x/*.xml" ]]; then
                                     ln -nsf $x ${POLLDEST}/
                                   fi
                                done
                            else
                                ln -nsf ${GPOLLDIR_ALT} ${POLLDEST}
                            fi
                        fi
        #fi
        #ls -l $LPOLLDIR
        
        #if [[ -e ${GPOLLDIR} ]]; then
        #    ln -nsf ${GPOLLDIR} ${LBUILD}
        #else
        #    ln -nsf ${GPOLLDIR_ALT} ${LBUILD}
        #fi
        #ln -sf ${GPOLLDIR} ${LPOLLDIR}
        ln -sf ${PRD_GENPROGSRC_DIR}/repair ${LBUILD}/genprog
        chmod +x ${GTEST}
    fi
}

if [ $ALLCBS -eq 1 ]; then 
index=0
for chal in $DIR/challenges/*/; do
    CHAL="$(basename $chal)"
    (( index+=${#CHAL} ))
    (( $index > 80 )) && index=${#CHAL} && echo ""
    echo -n -e "$CHAL, "
    build_genprog_test $chal
    running_jobs=$( ps -a -u | egrep "$CHAL\$" | awk '{print $2}' )
    (( $(echo $running_jobs | wc -w)>0 )) && kill -9 $running_jobs
    echo "Killed $CHAL "$(echo $running_jobs | wc -w)" test-related jobs [ids:"$running_jobs"]"
done
echo ""

else 
for c in ${TESTLIST[*]}; do
    echo "Building test $c"
    chal=$DIR/challenges/$c
    chal_build="${BUILD_DIR}/challenges/${c}"
    if [[ -e $chal_build/$c ]] ; then
         #CHAL=$c
         #(( index+=${#CHAL} ))
         #(( $index > 80 )) && index=${#CHAL} && echo ""
         #echo -n -e "$CHAL, "
         build_genprog_test $chal
    else
        echo "--WARNING-- CB binary '$c' has not been built"
        echo "Skipping '$c'..."
    fi
done

fi

if (( $VERBOSE > 0 )) ; then
[ ${BUILD_GENPROG} -ne 1 ] && echo -e "\nPLEASE NOTE:\n\tONLY links for GenProg AFR use were regenerated." 
[ ${BUILD_GENPROG} -eq 1 ] && echo -e "\nPLEASE NOTE:\n\t'genprog' subdirectory was regenerated for GenProg AFR use."
else
echo ""
fi


