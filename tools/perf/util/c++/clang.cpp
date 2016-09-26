/*
 * llvm C frontend for perf. Support dynamically compile C file
 *
 * Inspired by clang example code:
 * http://llvm.org/svn/llvm-project/cfe/trunk/examples/clang-interpreter/main.cpp
 *
 * Copyright (C) 2016 Wang Nan <wangnan0@huawei.com>
 * Copyright (C) 2016 Huawei Inc.
 */

#include "clang/CodeGen/CodeGenAction.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Option/Option.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"
#include <memory>

#include "clang.h"
#include "clang-c.h"
#include "llvm-utils-cxx.h"
#include "util-cxx.h"

namespace perf {

static std::unique_ptr<llvm::LLVMContext> LLVMCtx;

using namespace clang;

static CompilerInvocation *
createCompilerInvocation(llvm::opt::ArgStringList CFlags, StringRef& Path,
			 DiagnosticsEngine& Diags)
{
	llvm::opt::ArgStringList CCArgs {
		"-cc1",
		"-triple", "bpf-pc-linux",
		"-fsyntax-only",
		"-ferror-limit", "19",
		"-fmessage-length", "127",
		"-O2",
		"-nostdsysteminc",
		"-nobuiltininc",
		"-vectorize-loops",
		"-vectorize-slp",
		"-Wno-unused-value",
		"-Wno-pointer-sign",
		"-x", "c"};

	CCArgs.append(CFlags.begin(), CFlags.end());
	CompilerInvocation *CI = tooling::newInvocation(&Diags, CCArgs);

	FrontendOptions& Opts = CI->getFrontendOpts();
	Opts.Inputs.clear();
	Opts.Inputs.emplace_back(Path, IK_C);
	return CI;
}

static std::unique_ptr<llvm::Module>
getModuleFromSource(llvm::opt::ArgStringList CFlags,
		    StringRef Path, IntrusiveRefCntPtr<vfs::FileSystem> VFS)
{
	CompilerInstance Clang;
	Clang.createDiagnostics();

	Clang.setVirtualFileSystem(&*VFS);

	IntrusiveRefCntPtr<CompilerInvocation> CI =
		createCompilerInvocation(std::move(CFlags), Path,
					 Clang.getDiagnostics());
	Clang.setInvocation(&*CI);

	std::unique_ptr<CodeGenAction> Act(new EmitLLVMOnlyAction(&*LLVMCtx));
	if (!Clang.ExecuteAction(*Act))
		return std::unique_ptr<llvm::Module>(nullptr);

	return Act->takeModule();
}

std::unique_ptr<llvm::Module>
getModuleFromSource(llvm::opt::ArgStringList CFlags,
		    StringRef Name, StringRef Content)
{
	using namespace vfs;

	llvm::IntrusiveRefCntPtr<OverlayFileSystem> OverlayFS(
			new OverlayFileSystem(getRealFileSystem()));
	llvm::IntrusiveRefCntPtr<InMemoryFileSystem> MemFS(
			new InMemoryFileSystem(true));

	/*
	 * pushOverlay helps setting working dir for MemFS. Must call
	 * before addFile.
	 */
	OverlayFS->pushOverlay(MemFS);
	MemFS->addFile(Twine(Name), 0, llvm::MemoryBuffer::getMemBuffer(Content));

	return getModuleFromSource(std::move(CFlags), Name, OverlayFS);
}

std::unique_ptr<llvm::Module>
getModuleFromSource(llvm::opt::ArgStringList CFlags, StringRef Path)
{
	IntrusiveRefCntPtr<vfs::FileSystem> VFS(vfs::getRealFileSystem());
	return getModuleFromSource(std::move(CFlags), Path, VFS);
}

std::unique_ptr<llvm::SmallVectorImpl<char>>
getBPFObjectFromModule(llvm::Module *Module)
{
	using namespace llvm;

	LLVMInitializeBPFTargetInfo();
	LLVMInitializeBPFTarget();
	LLVMInitializeBPFTargetMC();
	LLVMInitializeBPFAsmPrinter();

	std::string TargetTriple("bpf-pc-linux");
	std::string Error;
	const Target* Target = TargetRegistry::lookupTarget(TargetTriple, Error);
	if (!Target) {
		llvm::errs() << Error;
		return std::unique_ptr<llvm::SmallVectorImpl<char>>(nullptr);
	}

	llvm::TargetOptions Opt;
	TargetMachine *TargetMachine =
		Target->createTargetMachine(TargetTriple,
					    "generic", "",
					    Opt, Reloc::Static);

	Module->setDataLayout(TargetMachine->createDataLayout());
	Module->setTargetTriple(TargetTriple);

	std::unique_ptr<SmallVectorImpl<char>> Buffer(new SmallVector<char, 0>());
	raw_svector_ostream ostream(*Buffer);

	legacy::PassManager PM;
	if (TargetMachine->addPassesToEmitFile(PM, ostream,
					       TargetMachine::CGFT_ObjectFile)) {
		llvm::errs() << "TargetMachine can't emit a file of this type\n";
		return std::unique_ptr<llvm::SmallVectorImpl<char>>(nullptr);;
	}
	PM.run(*Module);

	return std::move(Buffer);
}

class ClangOptions {
	llvm::SmallString<PATH_MAX> FileName;
	llvm::SmallString<64> KVerDef;
	llvm::SmallString<64> NRCpusDef;
	char *kbuild_dir;
	char *kbuild_include_opts;
	char *clang_opt;
public:
	ClangOptions(const char *filename) : FileName(filename),
					     KVerDef(""),
					     NRCpusDef(""),
					     kbuild_dir(NULL),
					     kbuild_include_opts(NULL),
					     clang_opt(NULL)
	{
		llvm::sys::fs::make_absolute(FileName);

		unsigned int kver;
		if (!fetch_kernel_version(&kver, NULL, 0))
			KVerDef = "-DLINUX_VERSION_CODE=" + std::to_string(kver);

		int nr_cpus = llvm__get_nr_cpus();
		if (nr_cpus > 0)
			NRCpusDef = "-D__NR_CPUS__=" + std::to_string(nr_cpus);

		if (llvm_param.clang_opt)
			clang_opt = strdup(llvm_param.clang_opt);

		llvm__get_kbuild_opts(&kbuild_dir, &kbuild_include_opts);
		if (!kbuild_dir || !kbuild_include_opts) {
			free(kbuild_dir);
			free(kbuild_include_opts);
			kbuild_dir = kbuild_include_opts = NULL;
		}
	}

	~ClangOptions()
	{
		free(kbuild_dir);
		free(kbuild_include_opts);
		free(clang_opt);
	}

	static void fillCFlagsFromString(opt::ArgStringList &CFlags, char *s, bool check = false)
	{
		if (!s)
			return;

		SmallVector<StringRef, 0> Terms;
		StringRef Opts(s);
		Opts.split(Terms, ' ');

		for (auto i = Terms.begin(); i != Terms.end(); i++)
			s[i->end() - Opts.begin()] = '\0';

		for (auto i = Terms.begin(); i != Terms.end(); i++) {
			if (!check) {
				CFlags.push_back(i->begin());
				continue;
			}

			if (i->startswith("-I"))
				CFlags.push_back(i->begin());
			else if (i->startswith("-D"))
				CFlags.push_back(i->begin());
			else if (*i == "-include") {
				CFlags.push_back((i++)->begin());
				/* Let clang report this error */
				if (i == Terms.end())
					break;
				CFlags.push_back(i->begin());
			}
		}
	}

	void getCFlags(opt::ArgStringList &CFlags)
	{
		CFlags.push_back(KVerDef.c_str());
		CFlags.push_back(NRCpusDef.c_str());

		fillCFlagsFromString(CFlags, clang_opt);
		fillCFlagsFromString(CFlags, kbuild_include_opts, true);

		if (kbuild_dir) {
			CFlags.push_back("-working-directory");
			CFlags.push_back(kbuild_dir);
		}
	}

	const char *getFileName(void)
	{
		return FileName.c_str();
	}
};

}

extern "C" {
void perf_clang__init(void)
{
	perf::LLVMCtx.reset(new llvm::LLVMContext());
}

void perf_clang__cleanup(void)
{
	perf::LLVMCtx.reset(nullptr);
	llvm::llvm_shutdown();
}

int perf_clang__compile_bpf(const char *_filename,
			    void **p_obj_buf,
			    size_t *p_obj_buf_sz)
{
	using namespace perf;

	if (!p_obj_buf || !p_obj_buf_sz)
		return -EINVAL;

	ClangOptions Opts(_filename);
	llvm::opt::ArgStringList CFlags;

	Opts.getCFlags(CFlags);
	auto M = getModuleFromSource(std::move(CFlags), Opts.getFileName());
	if (!M)
		return  -EINVAL;
	auto O = getBPFObjectFromModule(&*M);
	if (!O)
		return -EINVAL;

	size_t size = O->size_in_bytes();
	void *buffer;

	buffer = malloc(size);
	if (!buffer)
		return -ENOMEM;
	memcpy(buffer, O->data(), size);
	*p_obj_buf = buffer;
	*p_obj_buf_sz = size;
	return 0;
}
}
