# Linux builds work with the CMake shipped by Debian 12 / Ubuntu 22.04+; the
# Windows and macOS presets (from obs-plugintemplate) need 3.28.
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
  cmake_minimum_required(VERSION 3.25...3.30)
else()
  cmake_minimum_required(VERSION 3.28...3.30)
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/common/bootstrap.cmake" NO_POLICY_SCOPE)

project(${_name} VERSION ${_version})

if(APPLE)
  enable_language(OBJCXX)
endif()

option(ENABLE_FRONTEND_API "Use obs-frontend-api for UI functionality" OFF)
option(ENABLE_QT "Use Qt functionality" OFF)

# OCR backends. Windows and macOS have zero-dependency OS OCR; Tesseract is
# the default on Linux and optional elsewhere.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(_tesseract_default ON)
else()
  set(_tesseract_default OFF)
endif()
option(ENABLE_TESSERACT "Build the Tesseract OCR backend" ${_tesseract_default})
option(ENABLE_NATIVE_OCR "Build the OS OCR backend (Windows.Media.Ocr / Apple Vision)" ON)
option(BUNDLE_TESSDATA "Download eng.traineddata (tessdata_fast) into data/tessdata" OFF)

include(compilerconfig)
include(defaults)
include(helpers)

add_library(${CMAKE_PROJECT_NAME} MODULE)

find_package(libobs REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE OBS::libobs)

if(ENABLE_FRONTEND_API)
  find_package(obs-frontend-api REQUIRED)
  target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE OBS::obs-frontend-api)
endif()

if(ENABLE_QT)
  find_package(Qt6 COMPONENTS Widgets Core)
  target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE Qt6::Core Qt6::Widgets)
  target_compile_options(
    ${CMAKE_PROJECT_NAME}
    PRIVATE $<$<C_COMPILER_ID:Clang,AppleClang>:-Wno-quoted-include-in-framework-header -Wno-comma>
  )
  set_target_properties(
    ${CMAKE_PROJECT_NAME}
    PROPERTIES AUTOMOC ON AUTOUIC ON AUTORCC ON
  )
endif()

target_sources(
  ${CMAKE_PROJECT_NAME}
  PRIVATE
    src/plugin-main.c
    src/pii-redact-filter.cpp
    src/pii-redact-filter.h
    src/core/image.cpp
    src/core/image.hpp
    src/core/pii-matcher.cpp
    src/core/pii-matcher.hpp
    src/core/pii-types.hpp
    src/core/rect.cpp
    src/core/region-tracker.cpp
    src/core/region-tracker.hpp
    src/ocr/ocr-engine.hpp
    src/ocr/ocr-factory.cpp
)
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE src)

set(_have_ocr OFF)

if(ENABLE_TESSERACT)
  find_package(Tesseract CONFIG QUIET)
  if(TARGET Tesseract::libtesseract)
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE Tesseract::libtesseract)
  else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(TESSERACT REQUIRED IMPORTED_TARGET tesseract)
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE PkgConfig::TESSERACT)
  endif()
  target_sources(${CMAKE_PROJECT_NAME} PRIVATE src/ocr/ocr-tesseract.cpp)
  target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE PII_HAVE_TESSERACT)
  set(_have_ocr ON)

  if(BUNDLE_TESSDATA)
    set(_tessdata "${CMAKE_CURRENT_SOURCE_DIR}/data/tessdata/eng.traineddata")
    if(NOT EXISTS "${_tessdata}")
      message(STATUS "Downloading eng.traineddata (tessdata_fast)...")
      file(
        DOWNLOAD
        "https://github.com/tesseract-ocr/tessdata_fast/raw/4.1.0/eng.traineddata"
        "${_tessdata}"
        SHOW_PROGRESS
        STATUS _dl_status
      )
      list(GET _dl_status 0 _dl_code)
      if(NOT _dl_code EQUAL 0)
        file(REMOVE "${_tessdata}")
        message(FATAL_ERROR "Failed to download eng.traineddata: ${_dl_status}")
      endif()
    endif()
  endif()
endif()

if(ENABLE_NATIVE_OCR AND WIN32)
  target_sources(${CMAKE_PROJECT_NAME} PRIVATE src/ocr/ocr-windows.cpp)
  set_source_files_properties(src/ocr/ocr-windows.cpp PROPERTIES COMPILE_OPTIONS "/bigobj")
  target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE PII_HAVE_WINRT_OCR)
  target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE WindowsApp)
  set(_have_ocr ON)
elseif(ENABLE_NATIVE_OCR AND APPLE)
  target_sources(${CMAKE_PROJECT_NAME} PRIVATE src/ocr/ocr-apple-vision.mm)
  set_source_files_properties(src/ocr/ocr-apple-vision.mm PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
  target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE PII_HAVE_APPLE_VISION)
  target_link_libraries(
    ${CMAKE_PROJECT_NAME}
    PRIVATE "$<LINK_LIBRARY:FRAMEWORK,Vision.framework>" "$<LINK_LIBRARY:FRAMEWORK,CoreGraphics.framework>"
            "$<LINK_LIBRARY:FRAMEWORK,Foundation.framework>"
  )
  set(_have_ocr ON)
endif()

if(NOT _have_ocr)
  message(WARNING "No OCR backend enabled - the filter will only black out frames in fail-safe mode.")
endif()

set_target_properties_plugin(${CMAKE_PROJECT_NAME} PROPERTIES OUTPUT_NAME ${_name})
