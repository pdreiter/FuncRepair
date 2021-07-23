#!/usr/bin/env bash

export CC=gcc
export CXX=g++
#./build.sh
#./genpolls.sh

#--------------------------------------------------------------------------------
# script: cgc_test_setup.bash
# description: this script performs two distinct actions:
#         1) Generates new APR/BinREPARED infrastructure content and initializes run directory
#     -OR-
#         2) Initializes run directory with previously built infrastructure content
#
#--------------------------------------------------------------------------------
# NOTE: You can probably run this anywhere, since I have safeguarded it with $DIR
#       which gets assigned the dirname ${BASH_SOURCE[0]} [directory of this script]
#--------------------------------------------------------------------------------
#   ./cgc_test_setup.bash -help
# should provide example command lines and parameter info
#
# for new CBs, recommended command line:
#   ./cgc_test_setup.bash -overwrite-all -v -python3 <new CB>
#
# to set up BinREPARED infrastructure for existing CBs, recommended command line:
#   ./cgc_test_setup.bash -all
#
#--------------------------------------------------------------------------------


DEBUG=0
DIR=$CGC_CB_DIR #$(cd "$(dirname ${BASH_SOURCE[0]})" && pwd)
SRC_DIR="${DIR}/challenges"
BUILD_DIR=$(realpath ${DIR}/build)
MYBUILD=$(basename ${BUILD_DIR})
dest="cgc_test"
poll_src="${CGC_CB_DIR}/polls"
BUILD_CGCTEST=0
BUILD_INDIVIDUAL_POS_TESTS=1
ALLCBS=0
VERBOSE=0
LIMIT=100
TESTLIST=()
full_testpath=0
pkldir="pkl"
help_info() {
  echo -e "\nUsage: $0 [-rundir=<DIR>] [-overwrite-all] [-v] [-test <CB1> -test <CB2> | -all] [--poll-src=<POLLS>]"
  echo -e "\nCommand line Parameters:\n"
  echo -e "-overwrite-all\tOverwrites all contents in 'cgc_test/<CB>' subdir."
  echo -e "-v            \tVerbose build messages"
  echo -e "-all          \tProcess ALL CBs!! "
  echo -e "-full-test-path   \tAdd full test path in test script"
  echo -e "--poll-src=<NAME> \tSpecify a different test source directory [default=$poll_src]\n"
  echo -e "-test <NAME>  \tProcess specific CB named NAME!! (can be specified multiple times)\n"
  echo -e "-rundir=<DIR> \tGenerates a testing directory under <DIR>\n"

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
args=("$@")
(( len=$# ))
(( $# > 0 )) && \
(( i = 0 ))
(( $# == 0 )) && help_info
while (( i < $len )); do  
if [[ "${args[$i]}" == "-help" || "${args[$i]}" == "-h" || "${args[$i]}" == "--help" ]]; then
    help_info
elif [[ "${args[$i]}" == "--dest="* ]]; then
    dest=$(echo "${args[$i]}" | perl -p -e's/\-\-dest=//')
elif [[ "${args[$i]}" == "-overwrite-all" ]]; then
  BUILD_CGCTEST=1
elif [[ "${args[$i]}" == "-full-test-path" ]]; then
    full_testpath=1
elif [[ "${args[$i]}" == "--poll-src="* ]]; then
    poll_src=$(realpath $(echo ${args[$i]} | perl -p -e's/\-\-poll\-src=//'))
    pkldir="pkl."$(basename $poll_src)
elif [[ "${args[$i]}" == "-rundir="* ]]; then
    RUNDIR=$(echo ${args[$i]} | perl -p -e's/\-rundir=//')
elif [[ "${args[$i]}" == "-all" ]]; then
    ALLCBS=1 && echo "Enabling generation for all Challenge Binaries"
elif [[ "${args[$i]}" == "-v" ]]; then
VERBOSE=1 && echo "Enabling verbose build"
elif [[ "${args[$i]}" == "\-test" ]]; then
(( i+=1 )) && TESTLIST+=( ${args[$i]} ) && echo "- ${args[$i]}"
else
TESTLIST+=( ${args[$i]} ) && echo "- ${args[$i]}"
fi
(( i+=1 ))
done
CGCTEST_DIR="${DIR}/$dest"
[ ! -e ${CGCTEST_DIR} ] && mkdir -p ${CGCTEST_DIR} && BUILD_CGCTEST=1
if ((  $BUILD_CGCTEST==1 )) ; then echo "Overwriting ALL contents in '$dest' CB subdir."; fi

build_cgctest(){
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
    GBUILD="${CGCTEST_DIR}/${CHAL}"
    LBUILD="${BUILD_DIR}/challenges/${CHAL}"
    GTEST="${GBUILD}/test.sh"
    GGENPROG_CFG="${GBUILD}/configuration-func-repair"
    GMAKE_INC="${GBUILD}/prd_include.mk"
    GMAKE="${GBUILD}/Makefile.prd"
    GSRC="${GBUILD}/decompiled_source.c"
    GHDR="${GBUILD}/decompiled_source.h"
    GSLD="${GBUILD}/script.ld"
    GTOOLDIR="${PRD_BASE_DIR}/tools/cb-multios"
    GCHALLENGEPOLLDIR="${poll_src}/${CHAL}"
    GPOLLDIR="${GCHALLENGEPOLLDIR}/poller"
    LPOLLDIR="${LBUILD}/poller"
    LGPOLLDIR="${GBUILD}/poller"
    cwd=$(pwd)
    # creating the compiler flags to pass into genprog and funcinsert
    if [ -d ${LBUILD} ]; then 
        build=$BUILD_CGCTEST
        [ ! -e ${GBUILD} ] && build=1 && mkdir -p ${GBUILD}
        [[ ! -e ${GTEST} || ! -e ${GMAKE} ]] && build=1
        POLLDEST=${LPOLLDIR}
		[[ -d ${POLLDEST} ]] && rm ${POLLDEST}
        ln -nsf $(realpath ${GPOLLDIR}) ${POLLDEST}
    
        #echo "$DIR/challenges/$CHAL"
        #cd "$DIR/challenges/$CHAL"
        echo "Using test content from $GPOLLDIR"
        cd "$LBUILD"
        if (( ${build} > 0 )); then 
            #if (( $ONLY_MAKEFILE==0 )); then
                echo -e "#!/bin/bash" > ${GTEST}
    			echo -e "\n###################################################" >> ${GTEST}
    			echo -e "# THIS SCRIPT HAS BEEN AUTOMATICALLY GENERATED BY" >> ${GTEST}
    			echo -e "#          cgc_test_setup.bash" >> ${GTEST}
    			echo -e "###################################################\n" >> ${GTEST}
                echo -e "\n# \$1 = EXE\n# \$2 = test name\n# \$3 = port" >> ${GTEST}
                echo -e "# \$4 = source name\n# \$5 = single-fitness-file name" >> ${GTEST}
                echo -e "# exit 0 = success" >> ${GTEST}
                echo -e "bin=\$1\ntst=\$2\n#trap 'kill \$(jobs -p)' EXIT" >> ${GTEST}
                echo -e "#exe=\"setarch \$(uname -m) -R \$bin\"" >> ${GTEST} 
                echo -e "\nexport LD_BIND_NOW=1\n" >> ${GTEST} 
                echo -e "\ncase \$tst in\n" >> ${GTEST}
                chmod +x ${GTEST}
                if (( ${BUILD_INDIVIDUAL_POS_TESTS} > 0 )); then
                    polldir=""
                    pdirs=$(ls -d ./poller/*)
                    #echo "pdirs=>${pdirs[*]}"
                    for polldir in ${pdirs[*]}; do
                        (( num_pos = num_pos_int ))
                        num_pos_int=0
                        if [[ "$polldir/machine.py" || -e "$polldir/GEN_00000_00001.xml" || -e "$polldir/POLL_00001.xml" || -e "$polldir/POLL_00000.xml" ]]; then
                            echo -e "Running positive tests on ${CHAL}"
                            prefix=""
                            #echo "${chal_build}/$polldir/GEN_00000_00001.xml" 
                            if [[ -e "${chal_build}/$polldir/GEN_00000_00001.xml" ]]; then 
                                echo "GEN"
                                prefix="GEN_00000"
                            elif [[ -e "${chal_build}/$polldir/POLL_00001.xml" || -e "$polldir/POLL_00000.xml" ]]; then
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
                            num_pos_x=1
                            while (( $num_pos_int <= $LIMIT )); do
                                x=$(printf "%05g" $i)
                                #echo -n "INDEX $i, $x"
                                chal_build="${LBUILD}"
                                pass=1
                                if [[ -e "${chal_build}/$polldir/${prefix}_${x}.xml" ]]; then 
                                pushd ${chal_build} > /dev/null
                                echo -n "$x"
                                pass=0
                                id=$CGC_CB_DIR/pkl/$CHAL/p$num_pos_x
                                if  [[ $DEBUG -ne 1 ]]; then
                                scriptout=$($GTOOLDIR/cb-replay.py --cbs $CHAL --timeout 5 --negotiate $polldir/${prefix}_${x}.xml --id $id > /dev/null)
                                pass=$?
                                fi
                                popd > /dev/null
                                fi
                                if (( $pass == 0 )); then 
                                    (( num_pos_int += 1 ))
                                    (( num_pos_x=num_pos+num_pos_int ))
                                    echo -e "p$num_pos_x)" >> ${GTEST}
                                    testname="$polldir/${prefix}_${x}.xml"
                                    if (( $full_testpath>0 )); then
                                        testname=$(realpath "$testname")
                                    fi
                                    echo -e "\t$GTOOLDIR/cb-replay.py --cbs \$bin --timeout 5 --negotiate ${testname}" >> ${GTEST}
                                    echo -e ";;" >> ${GTEST}
                                    #echo -n " (pass)"
                                    #echo "num_pos_x => $num_pos_x"
                                    #new_id=$CGC_CB_DIR/pkl/$CHAL/p$num_pos_x
                                    #mv -v $id.pkl $new_id.pkl
                                else
                                    echo -n " (fail)"
                                fi 
                                echo -n ", "
                                (( i+=1 ))
                                if (( $i > $last )); then
                                    break;
                                fi
                            done
                        else
                            echo -e "\nNo positive tests for $CHAL in $polldir"
                        fi
                    done
                    (( num_pos=num_pos_x ))
                fi
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
                    echo -e "\t$GTOOLDIR/cb-replay-pov.py --cbs \$bin --timeout 5 --negotiate ${pov}\n;;\nesac\n\nexit \$?" >> ${sTEST}
                    echo -e "\t$GTOOLDIR/cb-replay-pov.py --cbs \$bin --timeout 5 --negotiate ${pov}\n" >> ${GTEST}
                    echo -e ";;\n" >> ${GTEST}
    				fi
                done
				rm ${GTEST}.tmp
                echo -e "esac" >> ${GTEST}
                echo -e "\nexit \$?" >> ${GTEST}
    
			    perl -p -e"s/CGCBINARYEXE/$CHAL/" $PRD_BASE_DIR/tools/examples/configuration-func-repair > ${GGENPROG_CFG}
                echo -e "--pos-tests ${num_pos}" >> ${GGENPROG_CFG}
                for i in ${povs[*]}; do
                    s=${GBUILD}/configuration-func-repair-$i;
                    cp ${GGENPROG_CFG} $s;
                    echo "--neg-tests 1" >> $s;
                    echo "--test-script ./test-$i.sh" >> $s;
                done
                echo -e "--neg-tests ${num_neg}" >> ${GGENPROG_CFG}
	        #else
			#    num_neg=$(cat $GGENPROG_CFG | egrep '\-\-neg\-tests' | awk '{print $NF}')
			#    num_pos=$(cat $GGENPROG_CFG | egrep '\-\-pos\-tests' | awk '{print $NF}')
			#	povs=$(ls $GBUILD/test-pov*.sh | perl -pi "s/$GBUILD\/test-//g;s/\.sh//")
            #fi
			cp $PRD_BASE_DIR/tools/templates/Makefile.prd ${GMAKE}
			perl -p -e"s/CGCBINARYEXE/$CHAL/" $PRD_BASE_DIR/tools/templates/prd_include.mk > ${GMAKE_INC}
            #if (( $ONLY_MAKEFILE==0 )); then
            # GENERATING THE DECOMPILED SOURCE CODE FILE
			cp $PRD_BASE_DIR/tools/examples/decompiled_source.c ${GSRC}
            # GENERATING THE DECOMPILED SOURCE CODE HEADER
			cp $PRD_BASE_DIR/tools/examples/decompiled_source.h ${GHDR}
            # GENERATING THE LINKING CONSTRAINTS
			cp $PRD_BASE_DIR/tools/templates/script.ld ${GSLD}
			# Linking poller directory
			ln -sf $(realpath ${GPOLLDIR}) ${LGPOLLDIR}
            #fi
        fi
        cd $cwd
        if [[ ! -z $RUNDIR ]]; then
            if [[ -d $RUNDIR/$CHAL ]]; then rm -rf $RUNDIR/$CHAL; fi
            mkdir -p $RUNDIR/$CHAL
            cp $GBUILD/* $RUNDIR/$CHAL/ &> /dev/null
            link_dirs $CHAL $RUNDIR/$CHAL/
        fi
    fi
}

link_dirs(){
    chal=$1
    dest=$2
    CHAL=$(basename $chal)
    # G<name> <= source of link
    # L<name> <= dest of link
    GBUILD="${CGCTEST_DIR}/${CHAL}"
    LBUILD="${BUILD_DIR}/challenges/${CHAL}"

    for i in $CHAL ${CHAL}_patched poller pkl; do
        ln -sf $(realpath $LBUILD/$i) $dest/
    done
    for i in $(ls $LBUILD/pov*.pov) ; do
        ln -sf $(realpath $i) $dest/
    done
    ln -sf ${PRD_BASE_DIR}/tools/cb-multios $dest/tools
    ln -sf ${SRC_DIR}/${CHAL} $dest/cgc_src
    ln -sf ${PRD_GENPROGSRC_DIR}/repair ${LBUILD}/genprog
}

if [ $ALLCBS -eq 1 ]; then 
index=0
for chal in $DIR/challenges/*/; do
    CHAL="$(basename $chal)"
    (( index+=${#CHAL} ))
    (( $index > 80 )) && index=${#CHAL} && echo ""
    echo -n -e "$CHAL, "
    build_cgctest $chal
    running_jobs=$( ps -a -u | egrep "$CHAL\$" | awk '{print $2}' )
    (( $(echo $running_jobs | wc -w)>0 )) && kill -9 $running_jobs
    echo "Killed $CHAL "$(echo $running_jobs | wc -w)" test-related jobs [ids:"$running_jobs"]"
done
echo ""

else 
for c in ${TESTLIST[*]}; do
    echo -e "\nBuilding test $c"
    chal=$DIR/challenges/$c
    chal_build="${BUILD_DIR}/challenges/${c}"
    if [[ -e $chal_build/$c ]] ; then
         #CHAL=$c
         #(( index+=${#CHAL} ))
         #(( $index > 80 )) && index=${#CHAL} && echo ""
         #echo -n -e "$CHAL, "
         build_cgctest $chal
    else
        echo "--WARNING-- CB binary '$c' has not been built"
        echo "Skipping '$c'..."
    fi
done

fi

if (( $VERBOSE > 0 )) ; then
[ ${BUILD_CGCTEST} -ne 1 ] && echo -e "\nPLEASE NOTE:\n\tONLY links for APR use were regenerated." 
[ ${BUILD_CGCTEST} -eq 1 ] && echo -e "\nPLEASE NOTE:\n\t'genprog' subdirectory was regenerated for APR use."
else
echo ""
fi


