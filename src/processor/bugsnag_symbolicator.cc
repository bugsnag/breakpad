#include "common/scoped_ptr.h"
#include "simple_symbol_supplier.h"

#include <limits>

#include "google_breakpad/processor/basic_source_line_resolver.h"
#include "google_breakpad/processor/call_stack.h"
#include "google_breakpad/processor/minidump.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"
#include "google_breakpad/processor/stack_frame_cpu.h"
#include "google_breakpad/processor/stackwalker.h"

using google_breakpad::BasicSourceLineResolver;
using google_breakpad::CodeModule;
using google_breakpad::CodeModules;
using google_breakpad::Minidump;
using google_breakpad::MinidumpMemoryList;
using google_breakpad::MinidumpModuleList;
using google_breakpad::MinidumpProcessor;
using google_breakpad::MinidumpThreadList;
using google_breakpad::ProcessState;
using google_breakpad::scoped_ptr;
using google_breakpad::SimpleSymbolSupplier;
using google_breakpad::StackFrame;
using google_breakpad::StackFrameSymbolizer;

long HexToLong(string hex) {
  char * p;
  long n = strtol( hex.c_str(), & p, 16 );
  if ( * p != 0 ) {
      fprintf(stderr, "Failed to convert Hex to Long\n");
      exit(1);
  }
  return n;
}

void Symbolicate(string filename, string symbol_path, string uuid, string address) {
    // Apply a symbol supplier if we've been given one or more symbol paths (to allow the stack data to be used when walking the stacktrace)
    std::vector<string> supplied_symbol_paths;
    scoped_ptr<SimpleSymbolSupplier> symbol_supplier;
    supplied_symbol_paths.push_back(symbol_path);
    if (!supplied_symbol_paths.empty()) {
      symbol_supplier.reset(new SimpleSymbolSupplier(supplied_symbol_paths));
    }

    BasicSourceLineResolver resolver;
    MinidumpProcessor minidump_processor(symbol_supplier.get(), &resolver);

    // Increase the maximum number of threads and regions.
    MinidumpThreadList::set_max_threads(std::numeric_limits<uint32_t>::max());
    MinidumpMemoryList::set_max_regions(std::numeric_limits<uint32_t>::max());
    
    // Process the minidump.
    Minidump dump(filename);
    if (!dump.Read()) {
      fprintf(stderr, "failed to read minidump\n");
    }

    // Construct a frame using the relevant module and the address (adjusted with the module's base address)
    ProcessState process_state;
    StackFrameSymbolizer* symbolizer = new StackFrameSymbolizer(symbol_supplier.get(), &resolver);
    const CodeModules* code_modules = dump.GetModuleList()->Copy();
    const CodeModules* unloaded_modules = dump.GetModuleList()->Copy();

    StackFrame* frame = new StackFrame();

    bool module_found = false;
    
    int module_count = dump.GetModuleList()->module_count();
    for (int i = 0; i < module_count; i++) {
      const CodeModule* mod = code_modules->GetModuleAtIndex(i);
      if (mod->debug_identifier() == uuid) {
        frame->module = mod;
        module_found = true;
        break;
      }
    }
    if (!module_found) {
      fprintf(stderr, "Unable to find module\n");
      exit(1);
    }
    frame->instruction = frame->module->base_address() + HexToLong(address);

    // Symbolicate the frame
    symbolizer->FillSourceLineInfo(code_modules, unloaded_modules,
                                              process_state.system_info(),
                                              frame);
    
    // Print the results
    fprintf(stdout, "\n--- Symbolication Results ---\n");
    fprintf(stdout, "File: '%s'\n", frame->source_file_name.c_str());
    fprintf(stdout, "Line: %d\n", frame->source_line);
    fprintf(stdout, "Method: '%s'\n", frame->function_name.c_str());
    fprintf(stdout, "\n");
}

int main(int argc, const char* argv[]) {
  if (argc != 5) {
    fprintf(stderr, "Usage: bugsnag_symbolication <minidump> <path/to/symbols> <uuid> <address>\n");
    exit(1);
  }

  string minidump = argv[1];
  string symbols_path = argv[2];
  string uuid = argv[3];
  string address = argv[4];

  fprintf(stdout, "Symbolicating address '%s' in '%s' using symbols for '%s' from '%s'\n", address.c_str(), minidump.c_str(), uuid.c_str(), symbols_path.c_str());

  Symbolicate(minidump, symbols_path, uuid, address);

  return 0;
}