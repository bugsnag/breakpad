#ifndef STACKWALK_WRAPPER_H
#define STACKWALK_WRAPPER_H

#include <string.h>
#include <string>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

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

      void destroy();
  } Stackframe;

  typedef struct Stacktrace {
      int frameCount;
      Stackframe* frames;

      void destroy();
  } Stacktrace;

  typedef struct Exception {
      Stacktrace stacktrace;
      const char* errorClass;
      const char* crashAddress;

      void destroy();
  } Exception;

  typedef struct App {
      int duration;
      const char* binaryArch;

      void destroy();
  } App;

  typedef struct Device {
      const char* osName;
      const char* osVersion;

      void destroy();
  } Device;

  typedef struct Thread {
      int id;
      bool errorReportingThread;
      Stacktrace stacktrace;

      void destroy();
  } Thread;

  typedef struct Event {
      int threadCount;
      const char* temp;
      Exception exception;
      App app;
      Device device;
      Thread* threads;

      void destroy();
  } Event;

  typedef struct ModuleDetails {
      int moduleCount;
      char** moduleIds;
      char** moduleNames;

      void destroy();
  } ModuleDetails;

  typedef struct WrappedEvent {
    Event event;
    const char *pstrErr;

    void destroy();
  } WrappedEvent;

  typedef struct WrappedModuleDetails {
    ModuleDetails moduleDetails;
    const char *pstrErr;

    void destroy();
  } WrappedModuleDetails;

  WrappedModuleDetails GetModuleDetails(const char* minidump_filename);
  WrappedEvent GetEventFromMinidump(const char* filename, const int symbol_path_count, const char** symbol_paths);
  void FreeEvent(WrappedEvent* wrapped_event);
  void FreeModuleDetails(WrappedModuleDetails* wrapped_module_details);

#ifdef __cplusplus
}
#endif

#endif // STACKWALK_WRAPPER_H
