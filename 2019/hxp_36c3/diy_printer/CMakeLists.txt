cmake_minimum_required(VERSION 3.10)
project(ctf LANGUAGES C)

file(READ "password.txt" input_string)
message("Your input: ${input_string}")

set(possible_hash "9d5088c4c2122faeb533e75c2c0023ee8bd47e86ffcdbba808c2c8a8627b1b8f")
set(vm_program
"P003I013WI015O1O1RTO2TO2QBO2DE1E1I013O1P000BO1TO1P002LBO1TDE1E1E1I008P003LI004P005LO1P000BO1TO1P002LBO1TDE1E1E1I005O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1I010TI013O1O1NTP000BO2O2TQDO2TO2NDE1E1I002I005O1O1TNO2TO2NDO2O2NP002LDE1E1O1P000BO1TO1P002LBO1TDE1E1E1I009O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1I005P019I012VI003VO1O1TNO2TO2NDO2O2NP002LDE1E1I000O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P004I004VI014I004O1O1TNO2TO2NDO2O2NP002LDE1E1O1P000BO1TO1P002LBO1TDE1E1E1I012O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P003I001WI004I003O1O1RTO2TBO2DE1E1O1P000BO1TO1P002LBO1TDE1E1E1I014O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P014I005I007O1O1RTO2TBO2DE1E1O1O1RTO2TBO2DE1E1I013O1O1RTO2TBO2DE1E1I011O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P001I006O1O1NTP000BO2O2TQDO2TO2NDE1E1I001O1O1TNO2TO2NDO2O2NP002LDE1E1P001I007O1O1NTP000BO2O2TQDO2TO2NDE1E1I002WO1O1RTO2TO2QBO2DE1E1I007O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P011P001I013I014O1O1RTO2TBO2DE1E1HO1O1RTO2TBO2DE1E1I015O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1I012I006O1P000BO1TO1P002LBO1TDE1E1E1I012O1O1RTO2TBO2DE1E1I006O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P002I001WP002I014WO1O1RTO2TBO2DE1E1P001HI001O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1I004I001I003O1P000BO1TO1P002LBO1TDE1E1E1O1O1TNO2TO2NDO2O2NP002LDE1E1I008O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P001P001I009I000O1O1RTO2TBO2DE1E1WHI003O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P003I010I009O1P000BO1TO1P002LBO1TDE1E1E1HI004O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P007I006O1O1NTP000BO2O2TQDO2TO2NDE1E1P001I010TO1O1RTO2TBO2DE1E1HI010O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1I012I004O1O1RTO2TBO2DE1E1I002O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1")

set(program_stack "")
set(program_size 0)
set(instruction "")

string(LENGTH "${vm_program}" program_size)
math(EXPR instruction_pointer "0")

while(instruction_pointer LESS program_size)
    string(SUBSTRING "${vm_program}" ${instruction_pointer} 1 instruction)

    if( instruction STREQUAL "P" )

        math(EXPR instruction_pointer "${instruction_pointer} + 1")

        string(SUBSTRING "${vm_program}" ${instruction_pointer} 3 p_argument)
        math(EXPR instruction_pointer "${instruction_pointer} + 3")

        math(EXPR p_argument "${p_argument}")

        list(APPEND program_stack "${p_argument}")

    elseif( instruction STREQUAL "I" )

        math(EXPR instruction_pointer "${instruction_pointer} + 1")

        string(SUBSTRING "${vm_program}" ${instruction_pointer} 3 i_argument)
        math(EXPR instruction_pointer "${instruction_pointer} + 3")

        math(EXPR i_argument "${i_argument}")
        string(SUBSTRING "${input_string}" ${i_argument} 1 i_argument)

        set(i_ascii_code_one 20)

        while(i_ascii_code_one LESS 127)

            string(ASCII ${i_ascii_code_one} i_char_one)

            if("${i_char_one}" STREQUAL i_argument)

                set(i_argument ${i_ascii_code_one})
                break()

            endif()

            math(EXPR i_ascii_code_one "${i_ascii_code_one} + 1")

        endwhile()

        list(APPEND program_stack "${i_argument}")

    elseif( instruction STREQUAL "D" )

        math(EXPR instruction_pointer "${instruction_pointer} + 1")

        list(LENGTH program_stack d_stack_size)

        math(EXPR d_stack_size "${d_stack_size} - 1")
        list(GET program_stack ${d_stack_size} d_pop_one)
        list(REMOVE_AT program_stack ${d_stack_size})

        math(EXPR d_stack_size "${d_stack_size} - 1")
        list(GET program_stack ${d_stack_size} d_pop_two)
        list(REMOVE_AT program_stack ${d_stack_size})

        set(d_list_one "")
        set(d_index_one 0)
        set(d_value_one ${d_pop_one})

        while(d_index_one LESS 8)

            math(EXPR d_value_two "${d_value_one} & 1")
            list(APPEND d_list_one "${d_value_two}")
            math(EXPR d_value_one "${d_value_one} >> 1")

            math(EXPR d_index_one "${d_index_one} + 1")

        endwhile()

        set(d_value_two 0)
        set(d_value_one 0)

        while(d_value_one LESS 8)

            list(GET d_list_one ${d_value_one} d_index_one)

            if (NOT ${d_index_one})

                math(EXPR d_value_two "${d_value_two} + (1 << ${d_value_one})")

            endif()

            math(EXPR d_value_one "${d_value_one} + 1")

        endwhile()

        math(EXPR d_partial_one "${d_pop_one} ^ ${d_pop_two}")
        math(EXPR d_partial_two "${d_value_two} | ${d_pop_two}")
        math(EXPR d_partial_two "${d_partial_two} + ${d_partial_two}")
        math(EXPR d_partial_three "${d_value_two} * 2")

        math(EXPR d_result "255 & (${d_partial_one} + ${d_partial_two} - ${d_partial_three})")

        list(APPEND program_stack "${d_result}")

    elseif( instruction STREQUAL "B" )

        math(EXPR instruction_pointer "${instruction_pointer} + 1")

        list(LENGTH program_stack b_stack_size)

        math(EXPR b_stack_size "${b_stack_size} - 1")
        list(GET program_stack ${b_stack_size} b_top_one)
        list(REMOVE_AT program_stack ${b_stack_size})

        math(EXPR b_stack_size "${b_stack_size} - 1")
        list(GET program_stack ${b_stack_size} b_top_two)
        list(REMOVE_AT program_stack ${b_stack_size})

        math(EXPR b_top_two "-1 * ${b_top_two}")

        set(b_list_one "")
        set(b_index_one 0)
        set(b_value_one ${b_top_two})

        while(b_index_one LESS 8)

            math(EXPR b_value_two "${b_value_one} & 1")
            list(APPEND b_list_one "${b_value_two}")
            math(EXPR b_value_one "${b_value_one} >> 1")

            math(EXPR b_index_one "${b_index_one} + 1")

        endwhile()

        set(b_value_two 0)
        set(b_value_one 0)

        while(b_value_one LESS 8)

            list(GET b_list_one ${b_value_one} b_index_one)

            if (NOT ${b_index_one})

                math(EXPR b_value_two "${b_value_two} + (1 << ${b_value_one})")

            endif()

            math(EXPR b_value_one "${b_value_one} + 1")

        endwhile()

        math(EXPR b_partial_one "${b_top_one} & ${b_value_two}")
        math(EXPR b_partial_two "${b_top_one} & ${b_top_two}")

        math(EXPR b_result "255 & (${b_top_two} + ${b_partial_one} + ${b_partial_two})")

        list(APPEND program_stack "${b_result}")

    elseif( instruction STREQUAL "L" )

        math(EXPR instruction_pointer "${instruction_pointer} + 1")

        list(LENGTH program_stack l_stack_size)

        math(EXPR l_stack_size "${l_stack_size} - 1")
        list(GET program_stack ${l_stack_size} l_top_one)
        list(REMOVE_AT program_stack ${l_stack_size})

        math(EXPR l_stack_size "${l_stack_size} - 1")
        list(GET program_stack ${l_stack_size} l_top_two)
        list(REMOVE_AT program_stack ${l_stack_size})

        math(EXPR l_value_one "${l_top_two} ^ -1")
        math(EXPR l_value_two "0 - 2")
        set(l_result 0)

        while(l_top_one GREATER 0)

            math(EXPR l_value_three "${l_result} ^ -1")
            math(EXPR l_result "255 & (-${l_value_three} - ${l_value_one} + ${l_value_two})")

            math(EXPR l_top_one "${l_top_one} - 1")

        endwhile()

        list(APPEND program_stack "${l_result}")

    elseif( instruction STREQUAL "V" )

        math(EXPR instruction_pointer "${instruction_pointer} + 1")

        list(LENGTH program_stack v_stack_size)

        math(EXPR v_stack_size "${v_stack_size} - 1")
        list(GET program_stack ${v_stack_size} v_top_one)
        list(REMOVE_AT program_stack ${v_stack_size})

        math(EXPR v_stack_size "${v_stack_size} - 1")
        list(GET program_stack ${v_stack_size} v_top_two)
        list(REMOVE_AT program_stack ${v_stack_size})

        set(v_result 0)

        math(EXPR v_value_one "${v_top_two} * -1")
        math(EXPR v_value_two "${v_value_one} ^ -1")

        while(v_top_one GREATER_EQUAL v_top_two)

            math(EXPR v_value_three "${v_value_one} ^ ${v_top_one}")
            math(EXPR v_value_four "2 * (${v_value_two} | ${v_top_one})")
            math(EXPR v_value_five "2 * ${v_value_two}")
            math(EXPR v_top_one "${v_value_three} + ${v_value_four} - ${v_value_five}")
            math(EXPR v_result "${v_result} + 1")

        endwhile()

        list(APPEND program_stack "${v_result}")

    elseif( instruction STREQUAL "R" )

        math(EXPR instruction_pointer "${instruction_pointer} + 1")

        list(LENGTH program_stack r_stack_size)

        math(EXPR r_stack_size "${r_stack_size} - 1")
        list(GET program_stack ${r_stack_size} r_top_one)
        list(REMOVE_AT program_stack ${r_stack_size})

        math(EXPR r_stack_size "${r_stack_size} - 1")
        list(GET program_stack ${r_stack_size} r_top_two)
        list(REMOVE_AT program_stack ${r_stack_size})

        math(EXPR r_partial_one "${r_top_one} + ${r_top_two}")
        math(EXPR r_partial_two "${r_top_one} & ${r_top_two}")
        math(EXPR r_partial_three "${r_top_two} & ${r_top_one}")

        math(EXPR r_result "255 & (${r_partial_one} - ${r_partial_two} - ${r_partial_three})")

        list(APPEND program_stack "${r_result}")

    elseif( instruction STREQUAL "Q" )

        math(EXPR instruction_pointer "${instruction_pointer} + 1")

        list(LENGTH program_stack q_stack_size)

        math(EXPR q_stack_size "${q_stack_size} - 1")
        list(GET program_stack ${q_stack_size} q_top_one)
        list(REMOVE_AT program_stack ${q_stack_size})

        math(EXPR q_stack_size "${q_stack_size} - 1")
        list(GET program_stack ${q_stack_size} q_top_two)
        list(REMOVE_AT program_stack ${q_stack_size})

        set(q_list_one "")
        set(q_index_one 0)
        set(q_value_one ${q_top_one})

        while(q_index_one LESS 8)

            math(EXPR q_value_two "${q_value_one} & 1")
            list(APPEND q_list_one "${q_value_two}")
            math(EXPR q_value_one "${q_value_one} >> 1")
            math(EXPR q_index_one "${q_index_one} + 1")

        endwhile()

        set(q_value_two 0)
        set(q_value_one 0)

        while(q_value_one LESS 8)

            list(GET q_list_one ${q_value_one} q_index_one)

            if (NOT ${q_index_one})

                math(EXPR q_value_two "${q_value_two} + (1 << ${q_value_one})")

            endif()

            math(EXPR q_value_one "${q_value_one} + 1")

        endwhile()

        math(EXPR q_partial_one "${q_top_one} ^ ${q_top_two}")
        math(EXPR q_partial_two "${q_value_two} | ${q_top_two}")
        math(EXPR q_result "255 & (${q_partial_two} + ${q_partial_one} - ${q_value_two})")

        list(APPEND program_stack "${q_result}")

    elseif( instruction STREQUAL "N" )

        math(EXPR instruction_pointer "${instruction_pointer} + 1")

        list(LENGTH program_stack n_stack_size)

        math(EXPR n_stack_size "${n_stack_size} - 1")
        list(GET program_stack ${n_stack_size} n_top_one)
        list(REMOVE_AT program_stack ${n_stack_size})

        math(EXPR n_stack_size "${n_stack_size} - 1")
        list(GET program_stack ${n_stack_size} n_top_two)
        list(REMOVE_AT program_stack ${n_stack_size})

        set(n_list_one "")
        set(n_index_one 0)
        set(n_value_one ${n_top_two})

        while(n_index_one LESS 8)

            math(EXPR n_value_two "${n_value_one} & 1")
            list(APPEND n_list_one "${n_value_two}")
            math(EXPR n_value_one "${n_value_one} >> 1")
            math(EXPR n_index_one "${n_index_one} + 1")

        endwhile()

        set(n_value_two 0)
        set(n_value_one 0)

        while(n_value_one LESS 8)

            list(GET n_list_one ${n_value_one} n_index_one)

            if (NOT ${n_index_one})

                math(EXPR n_value_two "${n_value_two} + (1 << ${n_value_one})")

            endif()

            math(EXPR n_value_one "${n_value_one} + 1")

        endwhile()

        math(EXPR n_partial_one "0 - (${n_top_one} ^ ${n_top_two})")
        math(EXPR n_partial_two "${n_top_one} & ${n_value_two}")
        math(EXPR n_result "${n_partial_one} + ${n_partial_two} + ${n_top_two}")

        list(APPEND program_stack "${n_result}")

    elseif( instruction STREQUAL "H" )

        math(EXPR instruction_pointer "${instruction_pointer} + 1")

        list(LENGTH program_stack h_stack_size)

        math(EXPR h_stack_size "${h_stack_size} - 1")
        list(GET program_stack ${h_stack_size} h_top_one)
        list(REMOVE_AT program_stack ${h_stack_size})

        math(EXPR h_stack_size "${h_stack_size} - 1")
        list(GET program_stack ${h_stack_size} h_top_two)
        list(REMOVE_AT program_stack ${h_stack_size})

        math(EXPR h_top_one "255 & (${h_top_one} << ${h_top_two})")

        list(APPEND program_stack "${h_top_one}")

    elseif( instruction STREQUAL "W" )

        math(EXPR instruction_pointer "${instruction_pointer} + 1")

        list(LENGTH program_stack w_stack_size)

        math(EXPR w_stack_size "${w_stack_size} - 1")
        list(GET program_stack ${w_stack_size} w_top_one)
        list(REMOVE_AT program_stack ${w_stack_size})

        math(EXPR w_stack_size "${w_stack_size} - 1")
        list(GET program_stack ${w_stack_size} w_top_two)
        list(REMOVE_AT program_stack ${w_stack_size})

        math(EXPR w_top_one "${w_top_one} >> ${w_top_two}")

        list(APPEND program_stack "${w_top_one}")

    elseif( instruction STREQUAL "T" )

        math(EXPR instruction_pointer "${instruction_pointer} + 1")

        list(LENGTH program_stack t_stack_size)

        math(EXPR t_stack_size "${t_stack_size} - 1")
        list(GET program_stack ${t_stack_size} t_top_one)
        list(REMOVE_AT program_stack ${t_stack_size})

        set(t_list_one "")
        set(t_index_one 0)

        while(t_index_one LESS 8)

            math(EXPR IlllIIO00O "${t_top_one} & 1")
            list(APPEND t_list_one "${IlllIIO00O}")
            math(EXPR t_top_one "${t_top_one} >> 1")
            math(EXPR t_index_one "${t_index_one} + 1")

        endwhile()

        set(t_result 0)
        set(t_top_one 0)

        while(t_top_one LESS 8)

            list(GET t_list_one ${t_top_one} t_index_one)

            if (NOT ${t_index_one})

                math(EXPR t_result "${t_result} + (1 << ${t_top_one})")

            endif()

            math(EXPR t_top_one "${t_top_one} + 1")

        endwhile()

        list(APPEND program_stack "${t_result}")

    elseif( instruction STREQUAL "O" )

        math(EXPR instruction_pointer "${instruction_pointer} + 1")

        string(SUBSTRING "${vm_program}" ${instruction_pointer} 1 o_argument)
        math(EXPR instruction_pointer "${instruction_pointer} + 1")
        math(EXPR o_argument "${o_argument}")

        list(LENGTH program_stack o_stack_size)

        math(EXPR o_stack_size "${o_stack_size} - 1 - ${o_argument}")
        list(GET program_stack ${o_stack_size} o_value_one)

        list(APPEND program_stack "${o_value_one}")

    elseif( instruction STREQUAL "E" )

        math(EXPR instruction_pointer "${instruction_pointer} + 1")

        string(SUBSTRING "${vm_program}" ${instruction_pointer} 1 e_argument)
        math(EXPR instruction_pointer "${instruction_pointer} + 1")
        math(EXPR e_argument "${e_argument}")

        list(LENGTH program_stack e_stack_size)

        math(EXPR e_stack_size "${e_stack_size} - 1 - ${e_argument}")

        list(REMOVE_AT program_stack ${e_stack_size})

    endif()

endwhile()

list(GET program_stack 0 stack_first_element)
list(LENGTH program_stack main_stack_size)

if (${stack_first_element} OR ${main_stack_size} GREATER 1)

    message(FATAL_ERROR "wrong password :(")

endif()

list(GET possible_hash 0 hash_copy)
math(EXPR main_index_one "0")
string(LENGTH "${hash_copy}" s_LEN)
set(possible_hash "")

while(main_index_one LESS s_LEN)

    string(SUBSTRING "${hash_copy}" ${main_index_one} 1 main_char_one)
    math(EXPR main_index_one "${main_index_one} + 1")

    string(SUBSTRING "${hash_copy}" ${main_index_one} 1 main_char_two)
    math(EXPR main_index_one "${main_index_one} + 1")

    if (main_char_one STREQUAL "a" )
        set(main_char_one "10")
    elseif(main_char_one STREQUAL "b" )
        set(main_char_one "11")
    elseif(main_char_one STREQUAL "c" )
        set(main_char_one "12")
    elseif(main_char_one STREQUAL "d" )
        set(main_char_one "13")
    elseif(main_char_one STREQUAL "e" )
        set(main_char_one "14")
    elseif(main_char_one STREQUAL "f" )
        set(main_char_one "15")
    endif()

    if (main_char_two STREQUAL "a" )
        set(main_char_two "10")
    elseif(main_char_two STREQUAL "b" )
        set(main_char_two "11")
    elseif(main_char_two STREQUAL "c" )
        set(main_char_two "12")
    elseif(main_char_two STREQUAL "d" )
        set(main_char_two "13")
    elseif(main_char_two STREQUAL "e" )
        set(main_char_two "14")
    elseif(main_char_two STREQUAL "f" )
        set(main_char_two "15")
    endif()

    math(EXPR main_char_code "${main_char_one} * 16 + ${main_char_two}")
    list(APPEND possible_hash ${main_char_code})

endwhile()

set(main_bytes_list ${possible_hash})
set(decryption_key "")
set(decryption_index 0)

while(decryption_index LESS 32)

    list(GET main_bytes_list ${decryption_index} main_byte_one)
    math(EXPR main_index_mod "${decryption_index} % 16")
    string(SUBSTRING "${input_string}" ${main_index_mod} 1 input_char)
    set(main_input_code 20)

    while(main_input_code LESS 127)

        string(ASCII ${main_input_code} lIIIll0OO0)

        if("${lIIIll0OO0}" STREQUAL input_char)

            set(input_char ${main_input_code})
            break()

        endif()

        math(EXPR main_input_code "${main_input_code} + 1")

    endwhile()

    math(EXPR main_char_code "${input_char} ^ ${main_byte_one}")
    set(main_value_one ${main_char_code})
    set(main_hexdigits "0123456789abcdef")

    math(EXPR main_char_code "${main_value_one} % 16")
    string(SUBSTRING "${main_hexdigits}" ${main_char_code} 1 main_first_char)

    math(EXPR main_char_code "${main_value_one} / 16")
    string(SUBSTRING "${main_hexdigits}" ${main_char_code} 1 main_second_char)

    set(main_byte_hex "${main_second_char}${main_first_char}")
    string(APPEND decryption_key ${main_byte_hex})

    math(EXPR decryption_index "${decryption_index} + 1")

endwhile()

add_executable(decrypt_flag decrypt.c aes.c)

target_compile_definitions(decrypt_flag PRIVATE "DEC_KEY=\"${decryption_key}\"")

add_custom_command(TARGET decrypt_flag POST_BUILD
COMMAND ${CMAKE_COMMAND} -E echo "++++++++++++++++++++++++++"
COMMAND ${CMAKE_COMMAND} -E echo "+ let\\'s decrypt the flag +"
COMMAND ${CMAKE_COMMAND} -E echo "++++++++++++++++++++++++++"
COMMAND ${CMAKE_COMMAND} -E touch "${CMAKE_CURRENT_LIST_DIR}/decrypt.c"
COMMAND ${CMAKE_COMMAND} -E echo "======================================"
COMMAND decrypt_flag
COMMAND ${CMAKE_COMMAND} -E echo "======================================")
