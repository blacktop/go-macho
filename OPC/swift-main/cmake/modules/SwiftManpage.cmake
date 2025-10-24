include(CMakeParseArguments)

find_program(POD2MAN pod2man)

# Create a target to create a man page from a pod file.
#
# manpage(
#     SOURCE foobar.pod
#     PAGE_HEADER "text"
#     MAN_FILE_BASENAME foobar
#     MAN_SECTION N
#     INSTALL_IN_COMPONENT comp
#     )
function(manpage)
  cmake_parse_arguments(
      MP # prefix
      "" # options
      "SOURCE;PAGE_HEADER;MAN_FILE_BASENAME;MAN_SECTION;INSTALL_IN_COMPONENT" # single-value args
      "" # multi-value args
      ${ARGN})

  if(NOT POD2MAN)
    message(FATAL_ERROR "Need pod2man installed to generate man page")
  endif()

  set(output_file_name
      "${CMAKE_CURRENT_BINARY_DIR}/${MP_MAN_FILE_BASENAME}.${MP_MAN_SECTION}")

  add_custom_command_target(
      manpage_target
      COMMAND
        "${POD2MAN}" "--section" "${MP_MAN_SECTION}"
        "--center" "${MP_PAGE_HEADER}" "--release=\"swift ${SWIFT_VERSION}\""
        "--name" "${MP_MAN_FILE_BASENAME}"
        "--stderr"
        "${MP_SOURCE}" > "${output_file_name}"
      OUTPUT "${output_file_name}"
      DEPENDS "${MP_SOURCE}"
      ALL)

  add_dependencies(${MP_INSTALL_IN_COMPONENT} ${manpage_target})
  set(MANPAGE_DEST "share/")
  if("${SWIFT_HOST_VARIANT_SDK}" STREQUAL "OPENBSD")
    set(MANPAGE_DEST "")
  endif()
  swift_install_in_component(FILES "${output_file_name}"
                             DESTINATION "${MANPAGE_DEST}man/man${MP_MAN_SECTION}"
                             COMPONENT "${MP_INSTALL_IN_COMPONENT}")
endfunction()

