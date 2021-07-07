#ifndef STACKWALK_WRAPPER_H
#define STACKWALK_WRAPPER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

  typedef void (*Destroy)(void* self);

  typedef struct Stackframe {
      const char* filename;
      const char* method;
      const char* frameAddress;
      const char* loadAddress;
      const char* moduleId;
      const char* moduleName;
      const char* returnAddress;
      const char* symbolAddress;
      const char* codeFile;
      const char* trust;
      Destroy destroy;
  } Stackframe;

  typedef struct Stacktrace {
      int frameCount;
      Stackframe* frames;
      Destroy destroy;
  } Stacktrace;

  typedef struct Exception {
      Stacktrace stacktrace;
      const char* errorClass;
      const char* crashAddress;
      Destroy destroy;
  } Exception;

  typedef struct App {
      int duration;
      const char* binaryArch;
      Destroy destroy;
  } App;

  typedef struct Device {
      const char* osName;
      const char* osVersion;
      Destroy destroy;
  } Device;

  typedef struct Thread {
      int id;
      bool errorReportingThread;
      Stacktrace stacktrace;
      Destroy destroy;
  } Thread;

  typedef struct Event {
      int threadCount;
      const char* temp;
      Exception exception;
      App app;
      Device device;
      Thread* threads;
      Destroy destroy;
  } Event;

  typedef struct ModuleDetails {
      int moduleCount;
      char** moduleIds;
      char** moduleNames;
      Destroy destroy;
  } ModuleDetails;

  typedef struct WrappedEvent {
    Event event;
    const char *pstrErr;
    Destroy destroy;
  } WrappedEvent;

  typedef struct WrappedModuleDetails {
    ModuleDetails moduleDetails;
    const char *pstrErr;
    Destroy destroy;
  } WrappedModuleDetails;

  WrappedModuleDetails GetModuleDetails(const char* minidump_filename);
  WrappedEvent GetEventFromMinidump(const char* filename, const int symbol_path_count, const char** symbol_paths);
  void FreeEvent(WrappedEvent* wrapped_event);
  void FreeModuleDetails(WrappedModuleDetails* wrapped_module_details);

#ifdef __cplusplus
}
#endif

#endif // STACKWALK_WRAPPER_H
