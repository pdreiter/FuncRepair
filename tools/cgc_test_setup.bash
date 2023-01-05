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
cp $PRD_BASE_DIR/tools/cb-multios/CMakeLists.txt $DIR/CMakeLists.txt
SRC_DIR="${DIR}/challenges"
BUILD_DIR=$(realpath ${DIR}/build)
MYBUILD=$(basename -- ${BUILD_DIR})
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
  echo -e "--dest=<NAME> \tSpecify a different test output directory [default=$dest]\n"
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
    pkldir="pkl."$(basename -- $poll_src)
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

build_cgccb(){
    chal=$1
    BUILDIT=0
    CHAL=$(basename -- $chal)
    if [[ ! -d $BUILD_DIR/challenges/$CHAL ]]; then  BUILDIT=1;
    elif [[ ! -e $BUILD_DIR/challenges/$CHAL/$CHAL ]]; then  BUILDIT=2; fi
    [[ ! -d $BUILD_DIR ]] && mkdir -p $BUILD_DIR
    if (( $BUILDIT==1 )) ; then
        echo "[build_cgccb] Initializing $BUILD_DIR"
	    pushd $BUILD_DIR &> /dev/null
	    cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
	      -DCMAKE_VERBOSE_MAKEFILE=ON \
	      -DBUILD_SHARED_LIBS=ON \
	      -DBUILD_STATIC_LIBS=OFF \
	      -DCMAKE_C_COMPILER=gcc-8 \
	      -DCMAKE_ASM_COMPILER=gcc-8 \
	      -DCMAKE_CXX_COMPILER=g++-8 \
	      ../ &> /dev/null
	    popd &> /dev/null
        (( BUILDIT+=1 ))
    fi
    if (( $BUILDIT==2 )) ; then
        echo "[build_cgccb] Compiling $BUILD_DIR/challenges/$CHAL"
	    pushd $BUILD_DIR/challenges/$CHAL &> /dev/null
	    make &> make.log
        if (( $?!=0 )); then echo "$CHAL failed to compile."; cat make.log; fi
	    popd &> /dev/null
    fi	  
}

build_cgctest(){
    chal=$1
    num_pos=0
    num_pos_int=0
    num_pos_x=0
    num_neg_x=0
    num_neg=0
    index=$2
    povs=()
    CHAL=$(basename -- $chal)
	DARPA=$(egrep -w $CHAL $CGC_CB_DIR/tob2darpa.list | sed 's/.*,//');
	DARPA_DIR=$CGC_CB_DIR/darpa-samples/cqe-challenges/$DARPA
	POVXML=1
	fs=()
	if [[ ! -d $DARPA_DIR ]]; then 
	   if [[ -d $CGC_CB_DIR/darpa-samples/examples/$DARPA ]] ; then 
	   DARPA_DIR=$CGC_CB_DIR/darpa-samples/examples/$DARPA
	   else
	   POVXML=0
	   fi
	fi
    
	if (( $POVXML==1 )); then 
	   fs=$(find $DARPA_DIR -type f -name "POV*.xml" -o -name "POV*.povxml");
	fi
	if (( ${#fs[@]}==0 )); then POVXML=0; fi

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

    GORACLE="${GBUILD}/oracle"
    GORACLE_TSTS="${GBUILD}/tsts"
    chal_build="${BUILD_DIR}/challenges/${CHAL}"


    cwd=$(pwd)
    # creating the compiler flags to pass into genprog and funcinsert
    if [ ! -d ${LBUILD} ]; then echo -e "Skipping $CHAL --- not built!"; 
    elif [ -d ${LBUILD} ]; then 
        build=$BUILD_CGCTEST
        [ ! -e ${GBUILD} ] && build=1 && mkdir -p ${GBUILD}
        [[ ! -e ${GTEST} || ! -e ${GMAKE} ]] && build=1
        POLLDEST=${LPOLLDIR}
		[[ -L ${POLLDEST} ]] && rm ${POLLDEST}
        ln -nsf $(realpath ${GPOLLDIR}) ${POLLDEST}
    
        #echo "$DIR/challenges/$CHAL"
        #cd "$DIR/challenges/$CHAL"
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

            	echo -ne '#!/bin/bash\n' > $GORACLE
				chmod +x $GORACLE
            	echo -ne 'SCRIPT_DIR=$(dirname -- $(realpath -- $0))\n' >> $GORACLE
            	echo -ne 'i='$CHAL'\n' >> $GORACLE
            	echo -ne 'if (( ${#ARGV[@]}>=2 )); then\n   bin=$1; TEST=$2; MAX=$3;\n' >> $GORACLE
            	echo -ne 'else\n   TEST=$1; \nfi\n' >> $GORACLE
            	echo -ne 'if [[ -z $MAX ]]; then MAX=1; fi\n' >> $GORACLE
            	echo -ne 'if [[ -z $bin ]]; then bin=$(realpath -- ./build/$i/$i); fi\n' >> $GORACLE
            	echo -ne 'TIMEOUT=5\n' >> $GORACLE
            	echo -ne 'if [[ ! -z $ANGELIX_RUN ]]; then TIMEOUT=50; fi; \n' >> $GORACLE
            	echo -ne 'TMP=/tmp/CGC_${RANDOM}_${i}_$RANDOM\nmkdir -p $(dirname -- $TMP)\n' >> $GORACLE
            	echo -ne 'assert-equal () {\n' >> $GORACLE
            	echo -ne '   for SEQ in $(seq 1 $MAX); do\n' >> $GORACLE
                echo -ne '\t( timeout --preserve-status -k $TIMEOUT $TIMEOUT $ANGELIX_RUN $1 < $2 ) > $TMP\n' >> $GORACLE
            	echo -ne '\tx=$?\n' >> $GORACLE
            	echo -ne '\tif (( $x >= 64 )); then rm $TMP ; exit $x; fi; \n' >> $GORACLE
            	echo -ne '\tbc=$(wc -c $3)\n' >> $GORACLE
            	echo -ne '\tcat $TMP | head -c $bc > $TMP.bc\n' >> $GORACLE
            	echo -ne '\tdiff -q $TMP.bc $3 > /dev/null\n' >> $GORACLE
            	echo -ne '\txx=$?\n\trm $TMP $TMP.bc\n\tif (( $xx!=0 )); then exit $xx; fi\n' >> $GORACLE
            	echo -ne '   done;\n   exit 0;\n' >> $GORACLE
            	echo -ne '\n}\n' >> $GORACLE
            	echo -ne '\ncase "$TEST" in \n' >> $GORACLE
				chmod +x $GORACLE
				mkdir -p $GORACLE_TSTS
            
                if (( $POVXML==0 )); then 
            	echo -ne '# no XML input for negative tests\n' >> $GORACLE
				else
            	echo -ne '# negative tests\n' >> $GORACLE
				ID=0;
				for f in $fs; do 
				    o=$($GTOOLDIR/cb-replay.py --cbs ${chal_build}/$CHAL --timeout 5 --negotiate $f --replay);
					x=$?

                    echo -n $(basename -- $f)
					if (( $x==1 )); then 
					    (( ID+=1 ));
						cp seed.log $GORACLE_TSTS/seed.n$ID
						cp replay.log $GORACLE_TSTS/n$ID.in
						cp replay.out.log $GORACLE_TSTS/n$ID.out.min
						o=$(seed=$(cat $GORACLE_TSTS/seed.n$ID | head -n1) \
						  timeout --preserve-status -k 5 5 ${chal_build}/${CHAL}_patched < $GORACLE_TSTS/n$ID.in \
						    > $GORACLE_TSTS/n$ID.out 2> /dev/null)
                        # if the file is empty, move the replay.out.log based one 
                        if [[ ! -s $GORACLE_TSTS/n$ID.out ]]; then 
                           cp $GORACLE_TSTS/n$ID.out.min $GORACLE_TSTS/n$ID.out 
                        fi
						echo -ne "\nn$ID)\n$ID)" >> $GORACLE
						echo -ne "\n\texport seed=\$(cat \$SCRIPT_DIR/tsts/seed.n$ID | head -n1)" >> $GORACLE
						echo -ne "\n\tassert-equal \"\$bin\" \"\$SCRIPT_DIR/tsts/n$ID.in\" \"\$SCRIPT_DIR/tsts/n$ID.out\" " >> $GORACLE
						echo -ne "\n\t;;" >> $GORACLE
                        echo -n "(pass [neg test failed]), "
                    else
                        echo -n "(fail [neg test passed]), "
					fi
				done
				fi
            	echo -ne '# positive tests\n' >> $GORACLE
                if (( ${BUILD_INDIVIDUAL_POS_TESTS} > 0 )); then
                    polldir=""
                    pdirs=$(ls -d $GPOLLDIR/*)
                    #echo "pdirs=>${pdirs[*]}"
                    for polldir in ${pdirs[*]}; do
                        (( num_pos = num_pos_int ))
                        num_pos_int=0
                        XML_FILES=$(find $polldir -type f -name "*.xml" | sort -g)
                        if (( ${#XML_FILES[@]}>0 )); then 
                            #echo -e "Running positive tests on ${CHAL}"
                            prefix=""
                            if [[ -e "$polldir/GEN_00000_00001.xml" ]]; then 
                                echo "GEN"
                                prefix="GEN_00000"
                            elif [[ -e "$polldir/POLL_00001.xml" || -e "$polldir/POLL_00000.xml" ]]; then
                                #echo "POLL"
                                prefix="POLL"
                            fi
                            #echo "PREFIX => $prefix"
                            if [[ $prefix == "" ]]; then 
                                echo "No generated XML in $polldir"
                                continue
                            fi
                            first=$(ls $polldir/${prefix}_*.xml | sort -u | head -n1 | perl -p -e "s/^.*${prefix}_//;s/\.xml//;s/^0{0,4}//g")
                            last=$(ls $polldir/${prefix}_*.xml | sort -ur | head -n1 | perl -p -e "s/^.*${prefix}_//;s/\.xml//;s/^0{0,4}//g")
    
                            #echo "polldir = $polldir"
                            #echo "PREFIX = $prefix"
                            #echo "first = $first"
                            #echo "last = $last"
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
                                pass=1
                                if [[ -e "$polldir/${prefix}_${x}.xml" ]]; then 
                                pushd ${chal_build} > /dev/null
                                echo -n "$x"
                                pass=0
                                id=$CGC_CB_DIR/$pkldir/$CHAL/p$num_pos_x
                                if  [[ $DEBUG -ne 1 ]]; then
                                scriptout=$($GTOOLDIR/cb-replay.py --cbs $CHAL --timeout 5 --negotiate $polldir/${prefix}_${x}.xml --id $id --replay > /dev/null)
                                pass=$?
                                fi
                                popd > /dev/null
                                fi
                                if (( $pass == 0 )); then 
									(( ID+= 1 ))
                                    (( num_pos_int += 1 ))
                                    (( num_pos_x=num_pos+num_pos_int ))
                                    echo -e "p$num_pos_x)" >> ${GTEST}
                                    testname="$polldir/${prefix}_${x}.xml"
                                    if (( $full_testpath>0 )); then
                                        testname=$(realpath "$testname")
                                    fi
                                    echo -e "\t$GTOOLDIR/cb-replay.py --cbs \$bin --timeout 5 --negotiate ${testname}" >> ${GTEST}
                                    echo -e ";;" >> ${GTEST}
            						cp ${chal_build}/seed.log $GORACLE_TSTS/seed.p$ID
            						cp ${chal_build}/replay.log $GORACLE_TSTS/p$ID.in
            						cp ${chal_build}/replay.out.log $GORACLE_TSTS/p$ID.out.min
            						o=$(seed=$(cat $GORACLE_TSTS/seed.p$ID | head -n1) \
            						  timeout --preserve-status -k 5 5 ${chal_build}/${CHAL}_patched < $GORACLE_TSTS/p$ID.in \
            						    > $GORACLE_TSTS/p$ID.out 2> /dev/null)
            						echo -ne "\np$num_pos_x)\n$ID)" >> $GORACLE
            						echo -ne "\n\texport seed=\$(cat \$SCRIPT_DIR/tsts/seed.p$ID | head -n1)" >> $GORACLE
            						echo -ne "\n\tassert-equal \"\$bin\" \"\$SCRIPT_DIR/tsts/p$ID.in\" \"\$SCRIPT_DIR/tsts/p$ID.out\" " >> $GORACLE
            						echo -ne "\n\t;;" >> $GORACLE
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
                echo -e "esac" >> ${GORACLE}
                # now Negative Tests
                povs=()
				neg_list=()
				cp ${GTEST} ${GTEST}.tmp
                for i in ${LBUILD}/pov*; do
                    pov=$(basename -- $i)
                    scriptout=$($GTOOLDIR/cb-replay-pov.py --cbs ${LBUILD}/$CHAL --timeout 5 --negotiate ${LBUILD}/${pov} > /dev/null)
                    pass=$?
                    scriptout=$($GTOOLDIR/cb-replay-pov.py --cbs ${LBUILD}/${CHAL}_patched --timeout 5 --negotiate ${LBUILD}/${pov} > /dev/null)
                    fail=$?
		    echo -e "[POV] $CHAL | ${pov} [$pass] [$fail] "
                    if (( $pass != 0 && $fail == 0 )); then 
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
			perl -p -e"s/<CGCBINARYEXE>/$CHAL/" $PRD_BASE_DIR/tools/templates/prd_include.mk > ${GMAKE_INC}
			perl -pi -e"s/<RECOMP_SRC>/decompiled_source/" ${GMAKE_INC}

            #if (( $ONLY_MAKEFILE==0 )); then
            # GENERATING THE DECOMPILED SOURCE CODE FILE
			cp $PRD_BASE_DIR/tools/examples/decompiled_source.c ${GSRC}
            # GENERATING THE DECOMPILED SOURCE CODE HEADER
			cp $PRD_BASE_DIR/tools/examples/decompiled_source.h ${GHDR}
            # GENERATING THE LINKING CONSTRAINTS
			cp $PRD_BASE_DIR/tools/templates/script.ld ${GSLD}
			# Linking poller directory
			[[ -L "${LGPOLLDIR}" ]] && rm $LGPOLLDIR
			ln -nsf $(realpath ${GPOLLDIR}) ${LGPOLLDIR}
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
    CHAL=$(basename -- $chal)
    # G<name> <= source of link
    # L<name> <= dest of link
    GBUILD="${CGCTEST_DIR}/${CHAL}"
    LBUILD="${BUILD_DIR}/challenges/${CHAL}"

    for i in $CHAL ${CHAL}_patched poller $pkldir; do
        [[ -e $LBUILD/$i ]] && ln -nsf $(realpath $LBUILD/$i) $dest/
    done
    for i in $(ls $LBUILD/pov*.pov) ; do
        ln -sf $(realpath $i) $dest/
    done
    ln -sf ${PRD_BASE_DIR}/tools/cb-multios $dest/tools
    ln -sf ${SRC_DIR}/${CHAL} $dest/cgc_src
    ln -sf ${PRD_GENPROGSRC_DIR}/repair ${LBUILD}/genprog
}

[[ ! -d $CGC_CB_DIR/darpa-samples ]] && git clone https://github.com/CyberGrandChallenge/samples.git $CGC_CB_DIR/darpa-samples
if [ $ALLCBS -eq 1 ]; then 
index=0
#build_cgccb ;
CNT=0
for chal in $DIR/challenges/*/; do
    (( CNT+=1 ))
    CHAL="$(basename -- $chal)"
    echo -ne "[$CNT] $CHAL : "
    chal_build="${BUILD_DIR}/challenges/${CHAL}"
    if [[ ! -e $chal_build/${CHAL} ]] ; then
        build_cgccb $chal_build
    fi
    if [[ ! -e $chal_build/$CHAL ]] ; then
        wcl=$(ls -1 $chal_build/$CHAL* 2> /dev/null | wc -l)
        l=$(basename -- $(ls -1 $chal_build/$CHAL* 2> /dev/null | head -n1))
        echo -ne "$chal_build/$CHAL doesn't exist. "
        if (( $wcl>0 )); then echo -ne " [$l does]. "; fi
        echo -e "Continuing."
        continue
    fi
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
    if [[ ! -e $chal_build/$c ]] ; then
        build_cgccb $chal_build
    fi
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


