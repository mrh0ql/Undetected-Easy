#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <ntstrsafe.h>

#include <deps/types.h>
#include <deps/defs.h>
#include <deps/entry.h>

#include <core/utility/utility.hxx>

#include <core/memory/pool/pool.hxx>
#include <core/memory/memory.hxx>
#include <core/utility/config.hxx>

#include <core/memory/paging/paging.hxx>
#include <core/memory/paging/remap.hxx>

#include <core/ioctl/commands.h>

#include <core/detections/whitelist.h>
#include <core/detections/signatures.h>

#include <core/detections/report/sha.h>
#include <core/detections/report/report.hxx>

#include <core/detections/module/disk.hxx>
#include <core/detections/module/protection.hxx>

#include <core/detections/memory/common.hxx>
#include <core/detections/memory/permissions.hxx>
#include <core/detections/memory/scan.hxx>
#include <core/detections/process/process.hxx>

#include <core/detections/execution/thread.hxx>
#include <core/detections/execution/processor.hxx>

#include <core/detections/callback/callback.hxx>
#include <core/detections/device/helpers.hxx>
#include <core/detections/device/device.hxx>

#include <core/detections/service/service.hxx>
#include <core/detections/cpu/cpu.hxx>
#include <core/detections/object/object.hxx>
#include <core/detections/dpc/dpc.hxx>
#include <core/detections/pool/pool.hxx>
#include <core/ioctl/ioctl.hxx>
