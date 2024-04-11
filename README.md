# Table of Contents
1. [FuncRepair](#funcrepair)
2. [Pre-requisite tools](#pre-requisite-tools)
2. [How to Set up](#how-to-set-up)
3. [Our approach to Binary Repair](#our-approach-to-binary-repair)
4. [Technical Impact of Source-level patching](#technical-impact-of-source-level-binary-patching)
5. [Evaluation Results](#evaluation-results)


# FuncRepair
function-based PRD (Partial Recompilation and Binary Rewriting) scripts for use with BinREPARED (a binary Automated Program Repair Framework)

For PRD decompilation support, see git submodule `partial_decompilation`


## Pre-requisite tools
* IDA - this is a proprietary decompiler, please link your ida decompiler to this directory: i.e. ln -sf \$IDADIR ida
* R - this is used for Coarse-Grained Fault Localization (CGFL), which re-implements RAFL (Motwani, 2020 [https://arxiv.org/abs/2011.08340]) using RankAggregation (merges 5 standard SBFL metrics into a single list)
  * Goto https://cran.r-project.org/ for installation information
* Other tools are installed by our initialization and set up script, `init.bash`

## How to set up
`source init.bash` 
* This sets up a python virtual environment that ensures that both the Python2 and Python3 requirements for the cb-multios (Linux) version of the DARPA CGC Challenge Binaries are installed
  * python3-ported versions of cb-multios scripts are located at:
  	* tools/cb-multios
* This clones/downloads ancillary repos/tarballs and prepares them for use with BinREPARED
  * glibc 2.31 source (reference content)
  * dietlibc (lightweight libc alternative)
  * cb-multios
  * R packages: RankAggreg, gtools [IFF R is installed]
  * APR
  	* GenProg for BinREPARED 
		* available as git submodule
  	* Prophet for BinREPARED
		* requires manual updates to official tar.gz image
		* see tools/apr/prophet/README.md
		* all provided scripts were tested with PRD with cb-multios
___
## Our approach to binary repair

Our approach centers on the idea that for most (if not all) binary programs, partial analysis is sufficient for binary repair. The following insights guided PRD: 
1. fault localization can identify a small set of functions relevant to the vulnerability;
2. decompilers can lift a small set of functions and compatible types to recompilable source code;
3. binary-source interfaces and binary rewriting can transform them into test-equivalent binaries, even when tools fail for full binaries;
4. the set of decompiled binary functions provide sufficient context to enable source-level analyses and transformations, even when those methods
only operate on source.

### PRD - a binary patching framework

We consider PRD a novel approach to automating binary repair that reduces the technical burden of binary repair and enables more human-centered analyses, by leveraging higher level source code as its binary repair content.

Our prototype focuses on x86, System-V ABI.
The following diagrams outline the description of high-level goals and the corresponding PRD stages.
<p>
<img src="imgs/prd_highlevel.png" width="50%" alt="High-level description of Stage requirements.">
</p>
<p>
<img src="imgs/prd_color.png" width="50%" alt="Stages of PRD.">
</p>


#### BinrePaiReD - an automated binary repair framework

We extend PRD to the task of automated binary repair by leveraging existing source-level APR tools with PRD methods and output in a framework we refer to as BinrePaiReD.
The following diagram outlines this framework as well as how existing PRD stages are leveraged.

<p>
<img src="imgs/binrepared_color.png" alt="Stages of BinrePaiReD" style="background-color:#FFFFFF">
<br><em> Stages of BinrePaiReD </em>
</p>

### Technical impact of source-level binary patching

Source-level binary patching poses additional requirements, as well as analytical and engineering difficulties. Specifically, PRD must ensure that all resulting binaries retain the same executional qualities as the original, such as the ability to call and use symbols regardless of their binding state. Binary-source interfaces allow decompiled code to execute original binary code, and, by using customized detours, original binary code to execute decompiled code. Although it does not recompile the original source code, PRD does compile the source code it generates, i.e., decompiled functions and binary-source interfaces (PRD decompiled code). Since compilers do not support combining new content with non-object binary content, PRD must effectively perform linking and locating with all new content, as well as translate function callees, each accomplished through binary rewriting.

#### PRD Execution Flows

Here, we depict high-level execution flows between original binary content and repair content as enabled by PRD.
While these flows outline interaction between binary components, we give examples in high-level source code for these interfaces in the next subsection.
<p>
<img src="imgs/detailed-prd-dataflow-light.png" width="70%" alt="PRD Binary Patch Execution Flows." style="background-color:#FFFFFF">
</p>
<p>
<img src="imgs/detailed-prd-explanation.png" width="60%" alt="Explanation of detour and the two complicated binary-source interfaces." style="background-color:#FFFFFF">
</p>


#### Example automatically generated binary-source interfaces

The following is an example of automatically generated binary-source interfaces for a CGC CB function `cgc_read_line` and its required symbols.
We note that, although the decompiler-definition has been omitted, `cgc_read_line`'s prototype is declared. 

* Example Unbound Symbol interface (`Bin-Src(plt)`)
```c
// Bin-Src(plt) : PLT register
unsigned int origPLT_EBX = NULL;

// Bin-Src(plt) : typedef function ptr 
typedef int (*pcgc_receive)(int s_0, int s_1, int s_2, int s_3);
pcgc_receive z__cgc_receive = NULL; 

// Bin-Src(plt) : Unbound Symbol interface 
int cgc_receive (int s_0,int s_1,int s_2,int s_3) {
    pcgc_receive lcgc_receive = z__cgc_receive;
    int ret;
    unsigned int localEBX;
    unsigned int localorigPLT_EBX = origPLT_EBX;
    asm ( "movl %[LOCALEBX],%%ebx\n\t"
          "movl %%ebx,%[PLT_EBX]\n\t"
          :[LOCALEBX] "=r"(localEBX)
          :[PLT_EBX] "r"(localorigPLT_EBX)
          : "%ebx");
    ret = lcgc_receive(s_0,s_1,s_2,s_3);
    asm ( "movl %%ebx,%[LOCALEBX]\n\t"
          :[LOCALEBX]"=r"(localEBX));
    return ret;
}
```
* Example Local Symbol interface (`Bin-Src(local)`)
```c
// Bin-Src(local) : typedef function ptr
typedef void * (*pcgc_memcpy)(void *, const void *, cgc_size_t);
pcgc_memcpy cgc_memcpy = NULL;

// Bin-Src(local) : typedef function ptr
typedef void * (*pcgc_calloc)(cgc_size_t);
pcgc_calloc cgc_calloc = NULL;
```
* Example Detour interface (`Bin-Src(dec)`) and Decompiled function prototype (`Decomp`)
```c
// Decomp : Decompiled Function Declaration
cgc_ssize_t  cgc_read_line(int fd, char **buf);

// Bin-Src(dec) : Detour Interface 
cgc_ssize_t  det_cgc_read_line( 
    // binary-source interface references
    void* EBX, void* mycgc_receive, void* mycgc_calloc, void* mycgc_memcpy,
    // parameters from Decompiled Function
    int fd, char * * buf )
{
    cgc_ssize_t retValue;
    origPLT_EBX = (unsigned int) EBX;
    z__cgc_receive = (pcgc_receive)(mycgc_receive);
    cgc_calloc = (pcgc_calloc)(mycgc_calloc);
    cgc_memcpy = (pcgc_memcpy)(mycgc_memcpy);

    retValue = cgc_read_line( fd, buf);
    asm( "mov    -0xc(%ebp),%eax\n\t"
         "mov    -0x4(%ebp),%ebx\n\t" "nop\n\t"
         "add    $0x14,%esp\n\t" "nop\n\t"
         "pop %ebx\n\t"
         "pop %ebp\n\t"
         "pop %ecx\n\t"
         "add $0xc,%esp\n\t"
         "push %ecx\n\t"
         "ret\n\t" 
    ); /* stack-correcting inline assembly */
    return retValue;
}
```

### Binary Rewriting

#### Aligning detour interface with binary function 

In the following excerpt from the generated binary-source interface code, we can see that the detour interface function prototype has diverged from the original binary function prototype:

```c
// Decomp : Decompiled Function Declaration
cgc_ssize_t  cgc_read_line(int fd, char **buf);

// Bin-Src(dec) : Detour Interface 
cgc_ssize_t  det_cgc_read_line( 
    // binary-source interface references
    void* EBX, void* mycgc_receive, void* mycgc_calloc, void* mycgc_memcpy,
    // parameters from Decompiled Function
    int fd, char * * buf );
```
In order to manage the difference in parameters between prototypes, binary rewriting inserts instructions before jumping to the detour interface.
These added instructions incur a byte-cost, `c`, for each additional reference, `r`, which may overrun the original function.
For our x86 implementation, our bytecost is `c=W+X+Y*r+Z=8r+9` when `r>0`, which does not include the jump to detour entry function.

| variable | description | number of machine instructions | byte-cost |
| -------- | ----------- | ---------------------- | --------- |
| `W`      | saves callframe | 1 | 1 |
| `X`      | gets and saves current offset | 2 | 6 |
| `Y`      | calculates relative address with current offset and pushes onto stack | 3 | 8 | 
| `Z`      | pushes `ebx` onto the stack | 1 | 1 |
| detour   | jump to detour entry function | 1 | 5 |


These instructions are generated and inserted during PRD's binary rewriting phase.

___
## Datasets used in our evaluation

<p>
<img src="imgs/prd_datasets.png" width="65%" alt="Datasets used in our evaluation">
</p>


___
## Evaluation Results

### Effectiveness of CGFL

As our strategy is reliant upon being capable of identifying a subset that contains the vulnerable function(s), we evaluated the capability of CGFL with function-spectra with our datasets.

* RQ1. Does CGFL identify function(s) relevant to the vulnerability?

Our results show that the CGFL output contains at least one ground-truth function for 95 of 100 CGC-C, 8 of 10 CGC-C++, and 196 of 206 Rode0day.
When accounting for all ground-truths, we see similar success: 74 CGC-C, 7 CGC-C++, and 196 Rode0day, which succeeds at 95% despite having few tests.
While CGFL succeeds more than 92\% with our criteria, when CGFL failed to identify a vulnerable function, we observed three failure types that can be readily explained or mitigated.
1. 14 binaries did not exercise any vulnerable function in any negative test.  
2. 10 were in the first three ranks, but ties impacted their selection, a common failure in SBFL metrics.
3. 1 buggily reimplemented a libc function.
Although 1. cannot be addressed by SBFL or by APR, 2. can readily mitigated by adding better test content or increasing the size of K for RankAggregation. 
Finally, 3. is a result of our simple heuristic that screens out known library functions, which could be replaced with a more sophisticated screening.

### Impact of Decompilation
Without any grammar or type restrictions, we evaluated baseline assumptions of decompiler quality, specifically looking at the following research questions
* RQ2. Without any restrictions, how often is decompiled code recompilable?
* RQ3. Is decompiled code behaviorally consistent to original binary functions?

<p>
<img src="imgs/prd_decompilation_impact.JPG" width="50%" alt="Impact of Decompilation Results" style="background-color:#000000">
<br><em> Impact of Decompilation Results </em>
</p>

<p>
<img src="imgs/recompilation_results.png" width="75%" alt="Basic recompilation results for decompiler output for binary functions, organized by optimization level with total function count.">
<br><em> Basic recompilation results for decompiler output for binary functions, organized by optimization level with total function count. SUCCESS
indicates successful recompilation.ERR-TYPE have type-related errors. ERR-CONSTR have language construction errors without type errors.
ERR-OTHER refers to other decompiler errors without type or construction </em>
</p>


<p>
<img src="imgs/perfunction_recompilation_success.png" width="50%" alt="Percentage of successful recompilations per binary with optimization level.">
<br><em>Percentage of successful recompilations per binary with optimization level. </em>
</p>


* We see that 11-57% of functions are impacted by decompiler issues even before evaluating semantics.  
These results reiterate the need for partial analyses, while decompiler tools are imperfect. (RQ1)
* We also see that, when decompilation succeeds, PRD largely generates test-equivalent binaries.
* It is not clear whether or not optimization level impacts recompilation success.

### Application to Automated Binary Repair using source-level APR algorithms

* RQ4. How effective is BinrePaiReD at mitigating vulnerabilities?


#### Full-source APR vs PRD-enabled APR

The following table summarizes the results of our APR evaluation comparing Full-source (baseline) to BinrePaiReD with PRD decompiled code (PRD). We report the number of scenarios that produced a plausible mitigation (mitigated), the total number that the APR tool successfully launched its search, as well as the number which the tool completed its search within 8 hours.
<p>
<img src="imgs/binrepaired_table_3_apr_comparison.PNG" width="60%" alt="BinrePaiReD results for 30 DARPA CGC Challenge Binaries.">
<br><em></em>
</p>

#### Impact of Source Code content on APR tools 

We investigated the impact of code content and structure on APR tools, comparing Full-source (baseline) vs PRD Decompiled code( PRD) vs Perfect Decompilation (``exact''), where the decompiled function was replaced with the original source code function.
In the following table, we outline these results for 30 DARPA Cyber Grand Challenge Binaries.

<p>
<img src="imgs/binrepaired_table_4_CGC_evaluation.JPG" width="120%" alt="BinrePaiReD results for 30 DARPA CGC Challenge Binaries.">
<br><em>BinrePaiReD results for 30 DARPA CGC Challenge Binaries for APR algorithms. </em>
</p>

