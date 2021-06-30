#!/usr/bin/env python3


import argparse
import os,copy,sys
import json
import pickle

import collections
import atexit

import numpy as np

# this requires pip install ordered-set
from ordered_set import OrderedSet

#try:
#    from collections import OrderedDict
#except ImportError:
#    OrderedDict = dict


debug=False
PRINT_ME=False
PICKLE_DATA=False
log=""
logfile="susp-default-pp.log"
bad_funcs=None
figure_name=None
script_dir=os.path.dirname(os.path.abspath(__file__))
cur_dir=os.getcwd()
d_name=os.path.basename(cur_dir)
name=d_name
rank_pkl_dir=None
rank_pkl_file=None

r_file=""

def parse_args():
    parser = argparse.ArgumentParser(description=\
    "Calculate suspiciousness from input dictionaries")
    parser.add_argument('--r-out',dest='r_outdir',action='store', default=".", help="Rscript output directory")
    parser.add_argument('--out',dest='outdir',action='store', default=".", help="Output directory")
    parser.add_argument('--in',dest='indir',action='store', default=".",
    help='Input directory to get dictionary inputs (expecting all.dict,p\d+.dict,n\d+.dict)')
    parser.add_argument('--ext',dest='ext',action='store', default='.dict')
    parser.add_argument('--all',dest='all',action='store', default='all')
    parser.add_argument('--max_rank',dest='max_rank',action='store', default=10)
    parser.add_argument('--all_rank',dest='all_rank',action='store_true', default=False)
    parser.add_argument('--dest',dest='dest_dir',action='store',default="susp_pkl_files.pp");
    parser.add_argument('--log',dest='log',action='store',default=None);
    parser.add_argument('--print',dest='print_me',action='store_true',default=False);
    parser.add_argument('--reduce',dest='reduce',action='store_true',default=False);
    parser.add_argument('--debug',dest='debug',action='store_true',default=False);
    parser.add_argument('--pickle',dest='pickle',action='store_true',default=False);
    parser.add_argument('--graphs',dest='graphs',action='store_true',default=False);
    parser.add_argument('--standardize',dest='standardize',action='store_true',default=False);
    parser.add_argument('--r_input',dest='r_input',action='store_true',default=False);
    parser.add_argument('--top-k-min',dest='top_k_min',action='store',default=10,
    help="Specifies top k minimum i.e. 'min(top_k_percent*size,10)'");
    parser.add_argument('--top-k-percent',dest='top_k',action='store',default=0.25,
    help="Specifies top percentage in decimal (default : 0.25 = 25%)");
    parser.add_argument('--cb',dest='cb',action='store',default=None)
    parser.add_argument('badfuncs',metavar="Fn",type=str,nargs='*')
    args = parser.parse_args()
    global name
    if args.cb:
        name=args.cb
    global PICKLE_DATA
    if args.pickle:
        PICKLE_DATA=args.pickle
    global PRINT_ME
    if args.print_me:
        PRINT_ME=args.print_me
    
    global logfile
    global rank_pkl_file 
    global rank_pkl_dir
    rank_pkl_dir=args.outdir+"/rank_pkl"
    if not os.path.exists(rank_pkl_dir):
          os.makedirs(rank_pkl_dir)
    rank_pkl_file=rank_pkl_dir+"/susp_metrics.pp.pkl"
    append=""
    if args.reduce:
        append=".reduced"
    if args.standardize:
        if len(append)>0:
            append+="-"
        else:
            append="."
        append+="std"
        rank_pkl_file=rank_pkl_dir+"/susp_metrics"+append+".pkl"
        logfile="susp-default"+append+".log"
    if args.log:
        logfile=args.log

    global debug
    debug=args.debug

    if args.badfuncs:
        global bad_funcs
        bad_funcs=args.badfuncs
        print(bad_funcs)
    if args.graphs:
        global figure_name
        figure_name=name
        if args.standardize:
            figure_name+="_standardized"
    if os.path.exists(logfile):
        os.remove(logfile);
    if args.r_input:
        global r_file
        r_dir=args.outdir+"/r"
        if args.r_outdir:
            r_dir=args.r_outdir
        r_file=r_dir+"/"+name+".r"
        full_r_dir=os.path.dirname(r_file)
        if not os.path.isdir(full_r_dir):
            os.makedirs(full_r_dir)

    return args

def sprint(*args,**kwargs):
    import io
    sio = io.StringIO()
    print(*args,**kwargs,file=sio)
    return sio.getvalue()

def logprint(*args, **kwargs):
    global log
    if debug:
        print(*args,**kwargs)
    log+=sprint(*args,**kwargs)

def write_log():
    with open(logfile,"a") as f:
        f.write(log)
        f.close()

def getFiles(indir,ext):
    x=[ i for i in os.listdir(indir) if ext in i ]
    return sorted(x)

def getDict(inf):
    #print("Opening {:s}".format(inf))
    with open(inf) as f:
        data=f.read()
        f.close()
    #return json.loads(data)
    import ast
    mydict=ast.literal_eval(data)
    # let's get rid of other inline functions
    alternate_fns = [k for k in mydict.keys() if "'" in k]
    if len(alternate_fns)>0:
        for a in alternate_fns:
            base=a.split("'",1)[0]
            if mydict.get(base,None):
                mydict[base]=mydict[a]
            else:
                mydict[base]+=mydict[a]
            del mydict[a]
    return mydict

def generate_plotdata(func_list,tarantula,ochiai,op2,barinel,dstar):
    for i,x in enumerate(func_list):
        t=tarantula[i]['value'];
        o=ochiai[i]['value'];
        op=op2[i]['value'];
        b=barinel[i]['value'];
        d=star[i]['value'];
        #gmetric_names_=['tarantula','ochiai','op^2','barinel','dstar']
        scores_=[t,o,op,b,d]
        for j,metric in enumerate(gmetric_names_):
            plotdata['fn'].append(x)
            plotdata['metric'].append(metric)
            plotdata['score'].append(scores_[j])
            if x in bad_funcs:
                badfn_plotdata['fn'].append(x)
                badfn_plotdata['metric'].append(metric)
                badfn_plotdata['score'].append(scores_[j])
        return plotdata,badfn_plotdata


def cmp_rand_tie_breaker(a,b):
    d=cmp(a,b)
    return d if d else random.randint(0,1)*2-1

def sort_valconf_rand(mylist):
    # let's randomize to switch up the whole stable sorting that python does
    import random
    random.shuffle(mylist)
    return sorted(mylist,key=lambda x: (x['value'],x['confidence']),reverse=True)

def scrutinize_and_sort(mylist):
    local_mylist = list()
    for x in mylist:
        if isinstance(x,dict):
            local_mylist.append(x)
        else:
            print("[DEBUG] Error with this entry: {} (type = {})".format(x,type(x)))
            sys.exit(-1);
    #return sorted(local_mylist,key=lambda x: (x['value'],x['confidence']),cmp=cmp_rand_tie_breaker,reverse=True)
    # let's randomize to switch up the whole stable sorting that python does
    import random
    random.shuffle(local_mylist)
    return sorted(local_mylist,key=lambda x: (x['value'],x['confidence']),reverse=True)

def example_plot(all_funcs,bad_funcs):
    import matplotlib.pyplot as plt
    import seaborn as sns
    np.random.seed(19680801)
    sns.set_style("whitegrid")
    #fig,ax = plt.subplots(nrows=1,ncols=len(metric_names_),sharey=True)
    print(bad_funcs)
    sns.violinplot(x='metric',y='score',data=all_funcs,inner=None,color=".85",title=metric,linewidth=.5)
    sns.stripplot(x='metric',y='score',data=bad_funcs,palette=sns.color_palette("Set2"),hue='fn',linewidth=.5)
    sns.despine(offset=5,trim=True)
    #sns.color_palette("husl",8)
    if name:
        plt.title("Developer Fixed Functions for '{}'".format(name))
        plt.suptitle("Distributions of CGFL Suspiciousness Scores")
        plt.savefig("{}.png".format(figure_name))
    plt.close()


def normalize(array):
    from sklearn import preprocessing
    import numpy as np
    x_array=np.array(array)
    norm_x=preprocessing.normalize([x_array])

def standardize(array):
    if len(array)==0:
        return array
    import numpy as np
    # generate 
    #tarantula.append(dict({ "name":x, "value":t, "confidence":confidence[x] }))
    values=np.array(array,dtype=float)
    div=np.ptp(values)
    vmin=np.min(values)
    vmax=np.max(values)
    stand=None
    if div==0 :
        stand=values/np.min(values)
    else:
        stand=(values-np.min(values))/np.ptp(values)
    return [stand.item(i) for i in range(0,len(array))]
    

def standardize_data(metric_array):
    #print("Changing entries to standard values [0,1] range")
    nm=standardize([i['value'] for i in metric_array])
    for i,v in enumerate(metric_array):
        #print("'{}' => '{}'".format(v['value'],nm[i]))
        metric_array[i]['value']=nm[i]
    return metric_array
    
def gen_prob_array(ar):
    import numpy as np
    ar__=standardize(ar)
    prob__=ar__/np.sum(ar__)
    return prob__
    
def gen_dist(eps,size,pos_array):
    import numpy as np
    ar=[eps for i in range(0,size)]
    for i in pos_array:
        ar[i]=1.
    ar__=np.asarray(ar,dtype=float)
    prob__=ar__/np.sum(ar__)
    return prob__


def kl(p,q,eps):
    p__=np.asarray(p,dtype=float)
    #p__=p__+eps
    q__=np.asarray(q,dtype=float)
    #q__=q__+eps
    from scipy.stats import entropy
    return entropy(p__,qk=q__)
    #divergence = np.sum(p__*np.log(p__/q__))
    #returnn
    


atexit.register(write_log)

args=parse_args();
all_keys=args.all+args.ext
mydictfiles=getFiles(args.indir,args.ext)

default=getDict(args.indir+"/"+all_keys)

fulldict=dict()
normalized_dict=dict()
passed_dict=dict()
failed_dict=dict()
total_failed=0.
total_passed=0.
func_list=sorted(default.keys())
print("FUNCTION LIST: "+str(func_list))

confidence=copy.copy(default)
#tarantula=copy.copy(default)
tarantula=list()
ochiai=list()
op2=list()
barinel=list()
dstar=list()

plotdata={'fn':list(),'metric':list(),'score':list()}
badfn_plotdata={'fn':list(),'metric':list(),'score':list()}

gmetric_names_=['tarantula','ochiai','op^2','barinel','dstar']

test_list=[os.path.splitext(i)[0] for i in sorted(mydictfiles) if i not in all_keys]
neg_tests=[]
pos_tests=[]

for i,x in enumerate(test_list):
    if x == all_keys:
        continue
    value=os.path.splitext(x)[0]
    new_dict=copy.copy(default)
    new_dict.update(getDict(args.indir+"/"+x+args.ext))

    fulldict[value]=copy.copy(new_dict)
    #print("Assigning "+value+" with "+str(new_dict))
    if "n" in value:
        neg_tests.append(value)
    elif "p" in value:
        pos_tests.append(value)


# let's get rid of pass test cases that have identical spectra to any fail case
# this data uses the raw callgrind data, not the translated spectra
# so this doesn't work :(
remove_me=set()
if args.reduce:
    spectra_dict=copy.copy(fulldict)
    for x in spectra_dict.keys():
        for y in spectra_dict[x].keys():
            if spectra_dict[x][y] > 0.:
               spectra_dict[x][y] = 1
    for n in neg_tests:
        neg_spectra=spectra_dict[n]
        for p in pos_tests:
            if neg_spectra == spectra_dict[p]:
                #remove_me.append(p)
                remove_me.add(p)
    
    if len(remove_me)>0:
        logprint("The following tests have identical spectra to negative tests.")
        logprint("Removing:")
    for r in remove_me:
        logprint(r)
        del fulldict[r]
        test_list.remove(r)

for i,x in enumerate(test_list):
    if x == all_keys:
        continue
    value=os.path.splitext(x)[0]
    try:
        fsum=sum(fulldict[value].values())
    except Exception as e:
        print(e)
        print("Test: "+str(value))
        print("Test values: "+str(fulldict[value].values()))
        raise
    factor=1.0
    if fsum != 0:
        factor=1.0/fsum
    normalized_dict[value]={k:v*factor for k,v in fulldict[value].items() }
    if 'p' in value:
        normalized_dict[value]['error']=0.0
        total_passed+=1.
    if 'n' in value:
        normalized_dict[value]['error']=1.0
        total_failed+=1.

if total_passed == 0:
    print("ERROR: Positive test content is missing!")
    logprint("ERROR: Positive test content is missing!")
    sys.exit(-1);

if total_failed == 0:
    print("ERROR: Negative test content is missing!")
    logprint("ERROR: Negative test content is missing!")
    sys.exit(-1);

for x in func_list:
    passed_dict[x]=0.
    failed_dict[x]=0.
    for y in test_list:
       if 'p' in y:
           passed_dict[x]+= 1. if fulldict[y][x]>0. else 0.
       if 'n' in y:
           failed_dict[x]+= 1. if fulldict[y][x]>0. else 0.

import math
for x in func_list:
    #plotdata={'fn':list(),'tarantula':list(),'ochiai':list(),'op2':list(),'barinel':list(),
    #'dstar':list(),'confidence':list()}
    confidence[x] = max(failed_dict[x]/total_failed,passed_dict[x]/total_passed)
    t=(failed_dict[x]/total_failed)/((failed_dict[x]/total_failed)+(passed_dict[x]/total_passed))
    o=(failed_dict[x])/math.sqrt(total_failed*(failed_dict[x]+passed_dict[x]))
    op=failed_dict[x] -(passed_dict[x]/(total_passed+1))
    b=1. -(passed_dict[x]/(passed_dict[x]+failed_dict[x]))
    d=1.
    if (passed_dict[x]+(total_failed-failed_dict[x]))!=0:
        d=(failed_dict[x]**2)/(passed_dict[x]+(total_failed-failed_dict[x]))

    
    #print("{} | {} | {} | {} | {} | {} | {} ".format(x,t,o,op,b,d,confidence[x]))
    tarantula.append(dict({ "name":x, "value":t, "confidence":confidence[x] }))
    ochiai.append(dict({ "name":x, "value":o, "confidence":confidence[x] }))
    op2.append(dict({ "name":x, "value":op, "confidence":confidence[x] }))
    barinel.append(dict({ "name":x, "value":b, "confidence":confidence[x] }))
    dstar.append(dict({ "name":x, "value":d, "confidence":confidence[x] }))

if args.standardize:
    #print("Before:"+str(op2))
    data=[tarantula,ochiai,op2,barinel,dstar]
    standdata=list()
    for j,metric in enumerate(gmetric_names_):
        standdata.append(standardize_data(data[j]))
    #print("After:"+str(standdata[2]))
    tarantula,ochiai,op2,barinel,dstar=standdata
if args.graphs:
    generate_plotdata(func_list,tarantula,ochiai,op2,barinel,dstar)
        
s_tarantula=scrutinize_and_sort(tarantula)
s_ochiai=scrutinize_and_sort(ochiai)
s_op2=scrutinize_and_sort(op2)
s_barinel=scrutinize_and_sort(barinel)
s_dstar=scrutinize_and_sort(dstar)
num_statements=len(confidence)
bad_funcs_expected=bad_funcs
bad_funcs_actual=None

if not bad_funcs or len(bad_funcs)<1:
    print("No ground truth, i.e. bad funcs, provided")
else:
    ranks=dict()
    #gmetric_names_=['tarantula','ochiai','op^2','barinel','dstar']
    for i in gmetric_names_:
        ranks[i]={
        'LIL':None, 
        'EXAM':list(),
        'Rank':list(),
        'Tarantula Rank':list(),
        'Tarantula Effectiveness':list(),
        'Steimann Rank':list()
        }


    bad_func_indices=[i for i,x in enumerate(func_list) if x in bad_funcs] 
    eps=10**-7
    L_=gen_dist(eps,num_statements,bad_func_indices)
    metrics__={ 'tarantula':s_tarantula,
                'ochiai':s_ochiai,
                'op^2':s_op2,
                'barinel':s_barinel,
                'dstar':s_dstar}
    for metric,mdata in metrics__.items():
        rank=0
        name_array=[elem['name'] for elem in mdata]
        value_array=[elem['value'] for elem in mdata]
        prob_dist=gen_prob_array(value_array)
        # Get KL distance for this metric
        ranks[metric]['LIL']=kl(value_array,L_,eps)   

        unique_values=OrderedSet(value_array)

        bad_func_names=[elem['name'] for elem in mdata if elem['name'] in bad_funcs]
        if not bad_funcs_actual:
            bad_funcs_actual=bad_func_names
        bad_func_values=[elem['value'] for elem in mdata if elem['name'] in bad_funcs]
        bad_func_norm_prob=[prob_dist[i] for i in bad_func_indices]
        bad_func_rank=dict()
        for i,bad in enumerate(bad_func_names):
            bad_func_rank[bad]=unique_values.index(bad_func_values[i])
            
        for i,bad in enumerate(bad_func_names):
            try:
                size=len(value_array)
                rank=bad_func_rank[bad]
                num_same=float(value_array.count(bad_func_values[i]))
                badfunc_same=float(bad_func_values.count(bad_func_values[i]))
                num_greater=float(sum(j>bad_func_values[i] for j in value_array))
                # Tarantula Rank Score
                # num scores greater than fault + number of scores equal to fault
                tar_rank=float(rank)+num_same

                # Tarantula Effectiveness Score 
                # [n-r(f)]/n [n : total number of elements, r(f) : tarantula rank score of fault]
                tar_eff_score=(size-tar_rank)/float(size)

                # EXAM Score
                # r(f)/n
                exam_score=tar_rank/float(size)

                # RANK Score
                # num scores greater + num_same/2
                rank_score=float(num_greater)+(float(num_same)/2.)

                # STEIMANN Rank Score
                # num greater + (num same + 1)/(num same faults + 1)
                steimann_score=num_greater+((num_same+1.)/(badfunc_same+1.))

                #ranks[i]={ 'LIL':None, 'EXAM':None, 'Rank':None, 'Tarantula Rank':None,
                #    'Tarantula Effectiveness':None, 'Steimann Rank':None }
                ranks[metric]['EXAM'].append(exam_score)
                ranks[metric]['Rank'].append(rank_score)
                ranks[metric]['Tarantula Rank'].append(tar_rank)
                ranks[metric]['Tarantula Effectiveness'].append(tar_eff_score)
                ranks[metric]['Steimann Rank'].append(steimann_score)

            except ValueError as v:
                print(v)
                pass
            except Exception as e:
                print("Unrecoverable exception!")
                print(e)
                raise

    import pickle
    pickle_data=None
    if os.path.exists(rank_pkl_file):
        pickle_data=pickle.load(open(rank_pkl_file,"rb"))
    else:
        pickle_data=dict()
    pickle_data[name]={
    'ranks':ranks,'metrics':metrics__,
    'bad_funcs_expected':bad_funcs_expected,
    'bad_funcs_actual':bad_funcs_actual,
    'func_list':func_list
    }
    with open(rank_pkl_file,'wb') as f:
        pickle.dump(pickle_data,f)
        f.close()
    
    

if PRINT_ME:
    logprint("{:10s}|{:21s}|{:21s}|{:21s}|{:21s}|{:21s}|".format("#","tarantula","ochiai","op2","barinel","dstar"))
    upper=int(args.max_rank)
    if args.all_rank:
        upper=len(s_tarantula)
    print("Printing top "+str(upper)+" results.");
    #print("type(s_tarantula) :"+str(type(s_tarantula)))
    #print("type(s_tarantula[0]) :"+str(type(s_tarantula[0])))
    #print("s_tarantula[0] :"+str(s_tarantula[0]))
    #print("type(tarantula) :"+str(type(tarantula)))
    for i in range(0,upper):
        if i >= len(s_tarantula):
            break
        s="{:10d}|{:15s} {:1.3f}|{:15s} {:1.3f}|{:15s} {:1.3f}|{:15s} {:1.3f}|{:15s} {:1.3f}|".format(i,
        s_tarantula[i]['name'],s_tarantula[i]['value'],
        s_ochiai[i]['name'],s_ochiai[i]['value'],
        s_op2[i]['name'],s_op2[i]['value'],
        s_barinel[i]['name'],s_barinel[i]['value'],
        s_dstar[i]['name'],s_dstar[i]['value'],
        )
        if bad_funcs:
            for fn in bad_funcs:
                import re
                s=re.sub(r"\|"+fn+" ",r"|"+fn+"* ",s)
        logprint(s)
    
    
if PICKLE_DATA:
    dest_dir=args.dest_dir
    
    
    if (not os.path.isdir(dest_dir)) and not os.path.dirname(dest_dir):
        dest_dir=os.getcwd()+"/"+dest_dir
    
    #print("[DEBUG] generating pickle content here: "+dest_dir+" ("+os.path.dirname(dest_dir)+")");
    if not os.path.isdir(dest_dir): 
        if os.path.isdir(os.path.dirname(dest_dir)):
            os.makedirs(dest_dir)
    
    if not os.path.isdir(dest_dir):
        print("Error! Having trouble generating destination directory: '"+dest_dir+"'")
        sys.exit(-1)
    
    with open(dest_dir+"/tarantula.pkl",'wb') as f:
        pickle.dump(tarantula,f)
        f.close()
    
    with open(dest_dir+"/ochiai.pkl",'wb') as f:
        pickle.dump(ochiai,f)
        f.close()
    
    with open(dest_dir+"/op2.pkl",'wb') as f:
        pickle.dump(op2,f)
        f.close()
    
    with open(dest_dir+"/barinel.pkl",'wb') as f:
        pickle.dump(barinel,f)
        f.close()
    
    with open(dest_dir+"/dstar.pkl",'wb') as f:
        pickle.dump(dstar,f)
        f.close()


if args.graphs:
    example_plot(plotdata,badfn_plotdata)

if args.r_input:
    # from R documentation:
    # R batch scripts
    rscript="#!/usr/bin/Rscript\n\n"
    rscript+="library(\"RankAggreg\")\n"
    rscript+="args = commandArgs(trailingOnly=TRUE) \n"
    rscript+="rseed = NULL\n"
    rscript+="if (length(args)==1) {\n     rseed = args[1]\n}\n"
    rscript+="ofile=paste(\""+name+"\",\""+str(args.top_k)+"\",paste(\"seed\",rseed,sep=\"_\"),\"results\",\"log\",sep=\".\")\n\n"
    # need to collect two sets of two dimensional arrays: functions and their metrics
    size=int(len(s_tarantula))
    #k_value=max(int((size*args.top_k)+0.5),10)
    k="size <- "+str(size)+"\n"
    k+="k_percent <- "+str(args.top_k)+"\n"
    k+="top_k <- c(as.integer((size*k_percent)+0.5), {})\n".format(args.top_k_min)
    k+="k <- min(c(max(top_k),size))\n"
    k+="N <- 10*size*size*size\n"
    if ( (size != len(s_ochiai)) and  
       (len(s_ochiai) != len(s_op2)) and  
       (len(s_op2) != len(s_barinel)) and  
       (len(s_barinel) != len(s_dstar)) 
    ):
        print("ERROR: length of arrays are different!")

    else:
        t_name= ",".join([ '"'+s_tarantula[i]['name']+'"' for i in range(0,size) ] )
        t_value= ",".join([ str(s_tarantula[i]['value']) for i in range(0,size) ] )
        o_name= ",".join([ '"'+s_ochiai[i]['name']+'"' for i in range(0,size) ] ) 
        o_value= ",".join([ str(s_ochiai[i]['value']) for i in range(0,size) ] )
        op_name= ",".join([ '"'+s_op2[i]['name']+'"' for i in range(0,size) ] )
        op_value= ",".join([ str(s_op2[i]['value']) for i in range(0,size) ] )
        b_name= ",".join([ '"'+s_barinel[i]['name']+'"' for i in range(0,size) ] )
        b_value= ",".join([ str(s_barinel[i]['value']) for i in range(0,size) ] )
        d_name= ",".join([ '"'+s_dstar[i]['name']+'"' for i in range(0,size) ] )
        d_value= ",".join([ str(s_dstar[i]['value']) for i in range(0,size) ] )
        #name_matrix="x <- matrix(c("+t_name+',\n'+o_name+',\n'+op_name+',\n'+b_name+',\n'+d_name+"),byrow=TRUE,ncol="+str(size)+")"
        name_matrix="\nx <- matrix(c({},\n{},\n{},\n{},\n{}),byrow=TRUE,ncol={})\n".format(
            t_name,o_name,op_name,b_name,d_name,str(size))
        weights_matrix="\nw <- matrix(c({},\n{},\n{},\n{},\n{}),byrow=TRUE,ncol={})\n".format(
            t_value,o_value,op_value,b_value,d_value,str(size))
        RankAggreg="\n(CES <- RankAggreg(x,k,weights=w, method=\"CE\", distance=\"Spearman\", seed=rseed, rho=.1, convIn=7,N=N))\n"
        plot="\n# plot(CES)\n"
        plot+="\ncat(unlist(unname(CES[1])),file=ofile)\n"
        with open(r_file,'w') as f:
            f.write(rscript)
            f.write(k)
            f.write(name_matrix)
            f.write(weights_matrix)
            f.write(RankAggreg)
            f.write(plot)
            f.close()
        os.chmod(r_file,0o755)
        print(str(os.path.realpath(r_file)),file=sys.stderr)

    

