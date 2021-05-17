#include "bugsnag_stackwalk_wrapper.h"

#include "common/scoped_ptr.h"
#include "logging.h"
#include "simple_symbol_supplier.h"

#include "google_breakpad/processor/basic_source_line_resolver.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"
#include "google_breakpad/processor/call_stack.h"
#include "google_breakpad/processor/stack_frame_cpu.h"

using google_breakpad::BasicSourceLineResolver;
using google_breakpad::CallStack;
using google_breakpad::HexString;
using google_breakpad::Minidump;
using google_breakpad::MinidumpMemoryList;
using google_breakpad::MinidumpModule;
using google_breakpad::MinidumpModuleList;
using google_breakpad::MinidumpProcessor;
using google_breakpad::MinidumpThreadList;
using google_breakpad::ProcessResult;
using google_breakpad::ProcessState;
using google_breakpad::scoped_ptr;
using google_breakpad::SimpleSymbolSupplier;
using google_breakpad::StackFrame;

// Gets the index of the thread that requested a dump be written
int getErrorReportingThreadIndex(const ProcessState& process_state) {
  int index = process_state.requesting_thread();
  // If the dump thread was not available then default to the first available thread
  if (index == -1) {
    index = 0;
  }
  return index;
}

// Maps the stacktrace information from a minidump into our Stacktrace struct
static Stacktrace getStack(int thread_num, const CallStack* stack)  {
  int frame_count = stack->frames()->size();

  std::vector<Stackframe> frames;

  for (int frame_index = 0; frame_index < frame_count; ++frame_index) {
    const StackFrame* frame = stack->frames()->at(frame_index);

    string frameAddress = HexString(frame->instruction);
    string returnAddress;
    string loadAddress = "";
    string filename = "";
    string moduleId = "";
    string moduleName = "";
    if (frame->module) {
      returnAddress = HexString(frame->ReturnAddress() - frame->module->base_address());
      loadAddress = HexString(frame->module->base_address());
      filename = frame->module->code_file();
      moduleId = frame->module->debug_identifier();
      moduleName = frame->module->debug_file();
    } else {
      returnAddress = HexString(frame->ReturnAddress());
    }
    
    Stackframe f = {
      .filename = strdup(filename.c_str()),
      .method = strdup(returnAddress.c_str()),
      .frameAddress = strdup(frameAddress.c_str()),
      .loadAddress = strdup(loadAddress.c_str()),
      .moduleId = strdup(moduleId.c_str()),
      .moduleName = strdup(moduleName.c_str())
    };
    frames.push_back(f);
  }

  Stackframe* stackframes = new Stackframe[frame_count];
  for (int frame_index = 0; frame_index < frame_count; ++frame_index) {
    stackframes[frame_index] = frames.at(frame_index);
  }

  Stacktrace s = {
    .frameCount = frame_count,
    .frames = stackframes
  };

  return s;
}

Thread* getThreads(const ProcessState& process_state) {
  int thread_count = process_state.threads()->size();
  int error_reporting_thread_index = getErrorReportingThreadIndex(process_state);

  Thread* threads = new Thread[thread_count];

  for (int i = 0; i < thread_count; i++) {
      const CallStack* thread = process_state.threads()->at(i);
      int thread_id = thread->tid();
      Thread t = {
        .id = thread_id,
        .stacktrace = getStack(i, thread),
        .errorReportingThread = (i == error_reporting_thread_index)
      };
      threads[i] = t;
  }

  return threads;
}

// Maps the information from a minidump into our Event struct
Event getEvent(const ProcessState& process_state) {
  Stacktrace s = getStack(1, process_state.threads()->at(getErrorReportingThreadIndex(process_state)));

  Exception e = {
    .stacktrace = s,
    .errorClass = strdup(process_state.crash_reason().c_str())
  };
  string crashAddress = HexString(process_state.crash_address());
  if (crashAddress != "") {
    e.crashAddress = strdup(crashAddress.c_str());
  }

  int uptime = 0;
  if (process_state.time_date_stamp() != 0 &&
      process_state.process_create_time() != 0 &&
      process_state.time_date_stamp() >= process_state.process_create_time()) {
    uptime = process_state.time_date_stamp() - process_state.process_create_time() * 1000;
  }

  App app = {
    .binaryArch = strdup(process_state.system_info()->cpu.c_str()),
    .duration = uptime // TODO - Handle this being empty
  };

  Device device = {
    .osName = strdup(process_state.system_info()->os.data()),
    .osVersion = strdup(process_state.system_info()->os_version.c_str())
  };
  
  int thread_count = process_state.threads()->size();
  Event returnEvent = {
    .exception = e,
    .app = app,
    .device = device,
    .threads = getThreads(process_state),
    .threadCount = thread_count
  };

  return returnEvent;
}

// Get the details of the modules in a minidump
WrappedModuleDetails GetModuleDetails(const char* minidump_filename) {
  WrappedModuleDetails result = {{0}};

  try {
    Minidump dump(minidump_filename);
    if (!dump.Read()) {
      result.pstrErr = strdup("failed to read minidump");
      return result;
    }

    MinidumpModuleList* module_list = dump.GetModuleList();
    if (!module_list) {
      result.pstrErr = strdup("failed to get module list");
      return result;
    }

    result.moduleDetails.moduleCount = module_list->module_count();

    char **module_ids = (char**)malloc(sizeof(char*) * module_list->module_count());
    char **module_names = (char**)malloc(sizeof(char*) * module_list->module_count());

    for (unsigned int i = 0; i < module_list->module_count(); i++) {
      const MinidumpModule* module = module_list->GetModuleAtIndex(i);

      module_ids[i] = (char*)malloc(sizeof(char) * strlen(module->debug_identifier().c_str()));
      strcpy(module_ids[i], module->debug_identifier().c_str());
      result.moduleDetails.moduleIds = module_ids;

      module_names[i] = (char*)malloc(sizeof(char) * strlen(module->debug_file().c_str()));
      strcpy(module_names[i], module->debug_file().c_str());
      result.moduleDetails.moduleNames = module_names;
    };
  } catch(const std::exception& ex) {
    string errMsg = "encountered exception: " + string(ex.what());
    result.pstrErr = strdup(errMsg.c_str());
  } catch(...) {
    result.pstrErr = strdup("encountered unknown exception");
  }

  return result;
}

// Gets a friendly version of a minidump processing failure reason
string getFriendlyFailureReason(ProcessResult process_result) {
  string reason = "";

  switch(process_result) {
    case google_breakpad::PROCESS_ERROR_MINIDUMP_NOT_FOUND:
      reason = "minidump not found";
      break;
    case google_breakpad::PROCESS_ERROR_NO_MINIDUMP_HEADER:
      reason = "no minidump header";
      break;
    case google_breakpad::PROCESS_ERROR_NO_THREAD_LIST:
      reason = "no thread list";
      break;
    case google_breakpad::PROCESS_ERROR_GETTING_THREAD:
      reason = "error getting thread";
      break;
    case google_breakpad::PROCESS_ERROR_GETTING_THREAD_ID:
      reason = "error getting thread ID";
      break;
    case google_breakpad::PROCESS_ERROR_DUPLICATE_REQUESTING_THREADS:
      reason = "more than one requesting thread";
      break;
    case google_breakpad::PROCESS_SYMBOL_SUPPLIER_INTERRUPTED:
      reason = "dump processing interrupted by symbol supplier";
      break;
    default:
      reason = "unknown failure reason";
  }

  return reason;
}

// Gets an Event payload from the minidump.
// Note: Logic for parsing the minidump is based on PrintMinidumpProcess in minidump_stackwalk.cc
// TODO - See if we can disable the logging output
WrappedEvent GetEventFromMinidump(const char* filename, const char* symbol_path) {
  WrappedEvent result = {{0}};

  try {
    // Apply a symbol supplier if we've been given a symbol path (to allow the stack data to be used when walking the stacktrace)
    scoped_ptr<SimpleSymbolSupplier> symbol_supplier;
    if (symbol_path != NULL && strlen(symbol_path) > 0) {
      symbol_supplier.reset(new SimpleSymbolSupplier(symbol_path));
    }

    BasicSourceLineResolver resolver;
    MinidumpProcessor minidump_processor(symbol_supplier.get(), &resolver);

    // Increase the maximum number of threads and regions.
    MinidumpThreadList::set_max_threads(std::numeric_limits<uint32_t>::max());
    MinidumpMemoryList::set_max_regions(std::numeric_limits<uint32_t>::max());
    
    // Process the minidump.
    Minidump dump(filename);
    if (!dump.Read()) {
      result.pstrErr = strdup("failed to read minidump");
      return result;
    }

    ProcessState process_state;
    ProcessResult process_result = minidump_processor.Process(&dump, &process_state);
    if (process_result != google_breakpad::PROCESS_OK) {
      string errMsg = "failed to process minidump: " + getFriendlyFailureReason(process_result);
      result.pstrErr = strdup(errMsg.c_str());
      return result;
    }

    // Map the process state to an Event struct
    result.event = getEvent(process_state);
  } catch(const std::exception& ex) {
    string errMsg = "encountered exception: " + string(ex.what());
    result.pstrErr = strdup(errMsg.c_str());
  } catch(...) {
    result.pstrErr = strdup("encountered unknown exception");
  }

  return result;
}

// Frees the memory allocated by an Event
// TODO - Check there are no memory leaks
void FreeEvent(WrappedEvent* wrapped_event) {
  wrapped_event->destroy();
}

// Frees the memory allocated by the module details
// TODO - Check there are no memory leaks
void FreeModuleDetails(WrappedModuleDetails* wrapped_module_details) {
  wrapped_module_details->destroy();
}