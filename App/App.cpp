/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include "../common/shared_macros.h"
#include "httplib.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>

sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_MEMORY_MAP_FAILURE,
        "Failed to reserve memory for the enclave.",
        NULL
    },
};

void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}


/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}


/* Auxiliary functions */
void split_output() {
    int len = 20;
    while(len) {
        std::cout << "-";
        len--;
    }
    std::cout << std::endl;
}

void reverse_byte_order(unsigned char* data, unsigned long length) {
    std::reverse(data, data + length);
}

std::string keyToString(const unsigned char* key, const size_t key_size){
    std::stringstream hex_stream;
    // 遍历每个字节并转换为十六进制
    for (size_t i = 0; i < key_size; ++i) {
        // 输出每个字节为两位十六进制数，确保输出格式为小写并填充零
        hex_stream << std::setw(2) << std::setfill('0') << std::hex << (int)key[i];
    }

    // 返回拼接好的十六进制字符串
    return hex_stream.str();
}

nlohmann::json parse_shuffled_transaction_string(const std::string &shuffled_transactions) {
    nlohmann::json split_data;
    size_t pos = 0;
    std::string token;
    std::string delimiter = ",";  // 用于分割地址:金额对
    std::string rest = shuffled_transactions;  // 用于存储剩余字符串

    while ((pos = rest.find(delimiter)) != std::string::npos) {
        token = rest.substr(0, pos);  // 提取每个 "address:amount" 对
        size_t colon_pos = token.find(":");  // 寻找 ":" 分隔符

        if (colon_pos != std::string::npos) {
            std::string address = token.substr(0, colon_pos);
            double amount = std::stod(token.substr(colon_pos + 1));  // 转换金额为 double
            split_data[address] = amount;  // 将地址和金额放入 JSON 对象
        }

        rest.erase(0, pos + delimiter.length());  // 剩余部分去除已处理的部分
    }

    // 处理最后一个部分（不含 "," 的最后一项）
    if (!rest.empty()) {
        size_t colon_pos = rest.find(":");
        if (colon_pos != std::string::npos) {
            std::string address = rest.substr(0, colon_pos);
            double amount = std::stod(rest.substr(colon_pos + 1));
            split_data[address] = amount;
        }
    }

    return split_data;
}

std::string getWarningMsg(int warning_sign) {
    if(warning_sign == TRANSACTION_NO_EXCEPTION) {
        return "No exception detected in the transaction.";
    }
    if(warning_sign == EXCESSIVE_SINGLE_AMOUNT) {
        return "Amount exceeds the maximum allowed for a single transaction.";
    }
    if(warning_sign == EXCESSIVE_DAILY_AMOUNT) {
        return "User's daily amount exceeds the maximum allowed for daily transactions.";
    }
    if(warning_sign == EXCESSIVE_FREQUENCY) {
        return "User's daily transaction frequency is too high.";
    }
}


/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

void ocall_file_exists(const char* filename, int* exists) {
    std::ifstream file(filename);
    if (file.is_open()) {
        *exists = 1;  // 文件存在
        file.close();
    } else {
        *exists = 0;  // 文件不存在
    }
}

void ocall_read_file(const char* filename, char* buffer, size_t buffer_size, int* ret) {
    std::ifstream wallet_file(filename, std::ios::in);
    if (wallet_file.is_open()) {
        wallet_file.read(buffer, buffer_size - 1);
        
        buffer[wallet_file.gcount()] = '\0';  // Null-terminate the string
        wallet_file.close();
        *ret = 0;
    } else {
		*ret = -1;
        std::cerr << "Error: fail to open file <" << filename << ">." << std::endl;
    }
}

void ocall_write_file(const char* filename, const char* data, size_t data_size, const int write_mode, int *ret) {
    std::string data_str(data);
    std::ios::openmode mode = std::ios::openmode(0);
    if(write_mode == OVER_WRITE_MODE) {
        mode |= std::ios::out;
    } else {
        mode |= std::ios::app;
    }

    std::ofstream wallet_file(filename, mode);
    if (wallet_file.is_open()) {
        wallet_file.write(data, strlen(data));
        if(wallet_file.fail()) {
            wallet_file.close();
            *ret = -1;
            std::cerr << "Error: fail to write to file <" << filename << ">." << std::endl;
            return;
        }
        *ret = 0;
        wallet_file.close();
    } else {
		*ret = -1;
        std::cerr << "Error: fail to open file <" << filename << ">." << std::endl;
	}
}


/* http handle functions */
void handle_add_request(const httplib::Request &req, httplib::Response &res) {
    std::cout << "Received a post request for addition." << std::endl;

    // 创建 JSON 响应数据
    nlohmann::json response_data;

    try {
        // 解析请求体中的 JSON 数据
        auto json_data = nlohmann::json::parse(req.body);

        // 提取 "data" 字段
        if (json_data.contains("data")) {
            std::string data = json_data["data"];
            std::cout << "data: " << data << std::endl;

            // 查找加号的位置
            unsigned long plus_pos = data.find('+');
            if (plus_pos != std::string::npos) {
                // 提取加号前后的字符串，转换为整数
                int a = std::stoi(data.substr(0, plus_pos));
                int b = std::stoi(data.substr(plus_pos + 1));

                // 调用加法运算（假设 ecall_add 已定义）
                int result = 0;
                ecall_add(global_eid, a, b, &result);  // 调用 Enclave 进行加法运算

                // 成功处理加法请求，构造响应
                response_data["message"] = "Addition successful";
                res.status = 200;  // 设置成功的 HTTP 状态码
                response_data["result"] = result;
                std::cout << "Addition result: " << result << std::endl;
            } else {
                // 如果没有找到加号
                response_data["message"] = "Invalid format. 'data' must be in the form 'a+b'.";
                res.status = 400;  // 设置错误的 HTTP 状态码
                std::cerr << "Invalid format. Missing '+' in the 'data' field." << std::endl;
            }
        } else {
            // 如果 "data" 字段不存在
            response_data["message"] = "Missing 'data' field in the request.";
            res.status = 400;  // 设置错误的 HTTP 状态码
            std::cerr << "Missing 'data' field in the request." << std::endl;
        }
    } catch (const nlohmann::json::exception &e) {
        // 捕获 JSON 解析错误
        response_data["message"] = "Invalid JSON format.";
        res.status = 400;  // 设置错误的 HTTP 状态码
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
    } catch (const std::exception &e) {
        // 捕获其他错误
        response_data["message"] = "Internel server error.";
        res.status = 500;  // 设置服务器错误的 HTTP 状态码
        std::cerr << "Error: " << e.what() << std::endl;
    }

    res.set_content(response_data.dump(), "application/json");
    split_output();
}

void handle_create_wallet_request(const httplib::Request &req, httplib::Response &res){
	std::cout << "Received a post request for creating a new wallet." << std::endl;
    
    // 创建 JSON 响应数据
    nlohmann::json response_data;

    try {
        // 解析请求体中的 JSON 数据
        auto json_data = nlohmann::json::parse(req.body);

        // 提取 wallet_id 字段
        if (json_data.contains("wallet_id")) {
            int wallet_id = json_data["wallet_id"];
            // std::cout << "wallet id: " << wallet_id << std::endl;

            // 初始化公钥和私钥
            unsigned char public_key[RSA_KEY_SIZE] = {0};
            unsigned char private_key[RSA_KEY_SIZE] = {0};

            // 调用 Enclave ECALL 函数来创建钱包
            int create_wallet_ret = -2;
            sgx_status_t ecall_create_ret = ecall_create_wallet(global_eid, public_key, private_key, 
                                                                RSA_KEY_SIZE, wallet_id, &create_wallet_ret);
            
            // 检查 ECALL 调用是否成功
            if (ecall_create_ret != SGX_SUCCESS) {
                print_error_message(ecall_create_ret);
                response_data["message"] = "Error while calling enclave function.";
                res.status = 500;  // 服务器内部错误
                res.set_content(response_data.dump(), "application/json");
                return;
            }

            // 反转公钥和私钥字节顺序
            reverse_byte_order(public_key, RSA_KEY_SIZE);
            reverse_byte_order(private_key, RSA_KEY_SIZE);

            // 将公钥和私钥转换为字符串
            std::string public_key_str = keyToString(public_key, RSA_KEY_SIZE);
            std::string private_key_str = keyToString(private_key, RSA_KEY_SIZE);

            // 根据 create_wallet_ret 的值判断创建钱包的结果
            if (create_wallet_ret == 0) {
                response_data["message"] = "wallet created successfully";
                response_data["public_key"] = public_key_str;
                response_data["private_key"] = private_key_str;
                res.status = 200;  // 请求成功
                std::cout << "Successfully created a new wallet." << std::endl;
            } else if (create_wallet_ret == -1) {
                response_data["message"] = "wallet id already existed";
                res.status = 400;  // 请求错误
                std::cerr << "Wallet ID already existed." << std::endl;
            } else {
                response_data["message"] = "Error while creating wallet";
                res.status = 400;  // 请求错误
                std::cerr << "Failed to create a new wallet." << std::endl;
            }
        } else {
            // 如果没有传递 wallet_id 字段
            response_data["message"] = "Missing 'wallet_id' field in the request.";
            res.status = 400;  // 请求错误
            std::cerr << "Missing 'wallet_id' field in the request." << std::endl;
        }
    } catch (const nlohmann::json::exception &e) {
        // 捕获 JSON 解析错误
        response_data["message"] = "Invalid JSON format.";
        res.status = 400;  // 请求错误
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
    } catch (const std::exception &e) {
        // 捕获其他异常
        response_data["message"] = "Internal server error.";
        res.status = 500;  // 服务器内部错误
        std::cerr << "Error: " << e.what() << std::endl;
    }

    // 返回响应
    res.set_content(response_data.dump(), "application/json");

    split_output();
}

void handle_deal_transaction_request(const httplib::Request &req, httplib::Response &res) {
    std::cout << "Received a POST request to shuffle transaction." << std::endl;
    
    // 创建 JSON 响应数据
    nlohmann::json response_data;

    try {
        // 解析请求体中的 JSON 数据
        auto json_data = nlohmann::json::parse(req.body);

        // 提取 "from", "to", 和 "amount" 字段
        if (json_data.contains("from") && json_data.contains("to") && json_data.contains("amount")) {
            int from = json_data["from"];
            int to = json_data["to"];
            double amount = json_data["amount"];

            // 调用 Enclave ECALL 函数来混洗交易
            char shuffled_transactions[MAX_TRANSACTION_SIZE];
            char shuffled_transactions_encrypted[MAX_TRANSACTION_ENCRYPTED_SIZE];
            int shuffle_ret = -1;  // 返回值，用于判断混洗是否成功
            int warning_sign = TRANSACTION_NO_EXCEPTION;
            sgx_status_t ecall_shuffle_ret = ecall_deal_transaction(global_eid, from, to, amount, 
                                                                    shuffled_transactions, sizeof(shuffled_transactions), 
                                                                    shuffled_transactions_encrypted, sizeof(shuffled_transactions_encrypted), 
                                                                    &warning_sign, &shuffle_ret);
            // 检查 ECALL 调用是否成功
            if (ecall_shuffle_ret != SGX_SUCCESS) {
                print_error_message(ecall_shuffle_ret);
                response_data["message"] = "Error while calling enclave function to shuffle transaction.";
                res.status = 500;  // 服务器内部错误
                res.set_content(response_data.dump(), "application/json");
                return;
            }

            // 根据 shuffle_ret 的值判断混洗结果
            if (shuffle_ret == 0) {
                response_data["message"] = "Transaction shuffled successfully.";
                
                // 解析 Enclave 返回的字符串，并将其转换为 JSON 格式
                std::string output_str(shuffled_transactions);
                nlohmann::json split_data = parse_shuffled_transaction_string(output_str);
                
                // 将拆分后的数据放入 "data" 字段
                response_data["data"] = split_data;
                std::string warningMsg = getWarningMsg(warning_sign);
                if(warning_sign != TRANSACTION_NO_EXCEPTION) {
                    response_data["transaction_status"] = "Exception";
                    response_data["warning_msg"] = warningMsg;
                } else {
                    response_data["transaction_status"] = "Success";
                }
                res.status = 200;  // 请求成功

                std::cout << "Warning sign: " << warning_sign << std::endl << "Message: " << warningMsg << std::endl;
            } else {
                response_data["message"] = "Error while shuffling transaction.";
                res.status = 400;  // 请求错误
                std::cerr << "Failed to shuffle transaction." << std::endl;
            }
        } else {
            // 如果缺少必要的字段
            response_data["message"] = "Missing required fields ('from', 'to', 'amount') in the request.";
            res.status = 400;  // 请求错误
            std::cerr << "Missing required fields in the request." << std::endl;
        }
    } catch (const nlohmann::json::exception &e) {
        // 捕获 JSON 解析错误
        response_data["message"] = "Invalid JSON format.";
        res.status = 400;  // 请求错误
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
    } catch (const std::exception &e) {
        // 捕获其他异常
        response_data["message"] = "Internal server error.";
        res.status = 500;  // 服务器内部错误
        std::cerr << "Error: " << e.what() << std::endl;
    }

    // 返回响应
    res.set_content(response_data.dump(), "application/json");

    split_output();  // 如果需要额外的输出
}

void handle_decrypt_transaction_request(const httplib::Request &req, httplib::Response &res) {
    std::cout << "Received a POST request to decrypt transaction." << std::endl;

    // 创建 JSON 响应数据
    nlohmann::json response_data;

    try {
        // 解析请求体中的 JSON 数据
        auto json_data = nlohmann::json::parse(req.body);

        // 提取 "from", "to", 和 "amount" 字段
        if (json_data.contains("from") && json_data.contains("to") && json_data.contains("amount")) {
            std::string encrypted_from = json_data["from"];
            std::string encrypted_to = json_data["to"];
            std::string encrypted_amount = json_data["amount"];


            // 将 JSON 字符串转换为 C 字符串
            const char* encrypted_from_cstr = encrypted_from.c_str();
            const char* encrypted_to_cstr = encrypted_to.c_str();
            const char* encrypted_amount_cstr = encrypted_amount.c_str();

            size_t encrypted_size = RSA_KEY_SIZE * 2 + 1;


            // 调用 Enclave ECALL 函数来解密交易数据
            int from_id = 0;
            int to_id = 0;
            double amount = 0.0;
            int ret = -1;  // 返回值，用于判断解密是否成功
            sgx_status_t ecall_ret = ecall_decrypt_transaction_data(global_eid, encrypted_from_cstr, 
                                                                    encrypted_to_cstr, encrypted_amount_cstr,
                                                                    encrypted_size, &from_id, &to_id, &amount, &ret);

            // 检查 ECALL 调用是否成功
            if (ecall_ret != SGX_SUCCESS) {
                std::cerr << "Error while calling enclave function to decrypt transaction." << std::endl;
                response_data["message"] = "Error while calling enclave function to decrypt transaction.";
                res.status = 500;  // 服务器内部错误
                res.set_content(response_data.dump(), "application/json");
                return;
            }

            // 根据 ret 的值判断解密结果
            if (ret == 0) {
                response_data["message"] = "Transaction decrypted successfully.";

                response_data["data"] = {
                    {"from", from_id},
                    {"to", to_id},
                    {"amount", amount}
                };
                res.status = 200;  // 请求成功
                std::cout << "Transaction decrypted successfully." << std::endl;

            } else {
                response_data["message"] = "Error while decrypting transaction.";
                res.status = 400;  // 请求错误
                std::cerr << "Failed to decrypt transaction." << std::endl;
            }
        } else {
            // 如果缺少必要的字段
            response_data["message"] = "Missing required fields ('from', 'to', 'amount') in the request.";
            res.status = 400;  // 请求错误
            std::cerr << "Missing required fields in the request." << std::endl;
        }
    } catch (const nlohmann::json::exception &e) {
        // 捕获 JSON 解析错误
        response_data["message"] = "Invalid JSON format.";
        res.status = 400;  // 请求错误
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
    } catch (const std::exception &e) {
        // 捕获其他异常
        response_data["message"] = "Internal server error.";
        res.status = 500;  // 服务器内部错误
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    // 返回响应
    res.set_content(response_data.dump(), "application/json");
    split_output();
}

void handle_encrypt_transaction_request(const httplib::Request &req, httplib::Response &res) {
    std::cout << "Received a POST request to encrypt transaction." << std::endl;
    
    // 创建 JSON 响应数据
    nlohmann::json response_data;

    try {
        // 解析请求体中的 JSON 数据
        auto json_data = nlohmann::json::parse(req.body);

        // 提取 "from", "to", 和 "amount" 字段
        if (json_data.contains("from") && json_data.contains("to") && json_data.contains("amount")) {
            int from = json_data["from"];
            int to = json_data["to"];
            double amount = json_data["amount"];

            // 调用 Enclave ECALL 函数来加密交易
            int encrypt_ret = -1;  // 返回值，用于判断加密是否成功
            sgx_status_t ecall_encrypt_ret = ecall_encrypt_transaction(global_eid, from, to, amount, &encrypt_ret);

            // 检查 ECALL 调用是否成功
            if (ecall_encrypt_ret != SGX_SUCCESS) {
                print_error_message(ecall_encrypt_ret);
                response_data["message"] = "Error while calling enclave function to encrypt transaction.";
                res.status = 500;  // 服务器内部错误
                res.set_content(response_data.dump(), "application/json");
                return;
            }

            // 根据 encrypt_ret 的值判断加密结果
            if (encrypt_ret == 0) {
                response_data["message"] = "Transaction encrypted successfully.";
                res.status = 200;  // 请求成功
                // std::cout << "Transaction encrypted successfully." << std::endl;
            } else {
                response_data["message"] = "Error while encrypting transaction.";
                res.status = 400;  // 请求错误
                std::cerr << "Failed to encrypt transaction." << std::endl;
            }
        } else {
            // 如果缺少必要的字段
            response_data["message"] = "Missing required fields ('from', 'to', 'amount') in the request.";
            res.status = 400;  // 请求错误
            std::cerr << "Missing required fields in the request." << std::endl;
        }
    } catch (const nlohmann::json::exception &e) {
        // 捕获 JSON 解析错误
        response_data["message"] = "Invalid JSON format.";
        res.status = 400;  // 请求错误
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
    } catch (const std::exception &e) {
        // 捕获其他异常
        response_data["message"] = "Internal server error.";
        res.status = 500;  // 服务器内部错误
        std::cerr << "Error: " << e.what() << std::endl;
    }

    // 返回响应
    res.set_content(response_data.dump(), "application/json");
    split_output();
}

void handle_transaction_warning_request(const httplib::Request &req, httplib::Response &res) {
    std::cout << "Received a POST request of transaction warning." << std::endl;
    
    // 创建 JSON 响应数据
    nlohmann::json response_data;

    try {
        // 解析请求体中的 JSON 数据
        auto json_data = nlohmann::json::parse(req.body);

        // 提取 "from", "to", 和 "amount" 字段
        if (json_data.contains("from") && json_data.contains("to") && json_data.contains("amount")) {
            int from = json_data["from"];
            int to = json_data["to"];
            double amount = json_data["amount"];

            // 调用 Enclave ECALL 函数来加密交易
            int encrypt_ret = -1;  // 返回值，用于判断加密是否成功
            int warning_sign = TRANSACTION_NO_EXCEPTION;
            sgx_status_t ecall_encrypt_ret = ecall_transaction_warning(global_eid, from, to, amount, &warning_sign, &encrypt_ret);

            // 检查 ECALL 调用是否成功
            if (ecall_encrypt_ret != SGX_SUCCESS) {
                print_error_message(ecall_encrypt_ret);
                response_data["message"] = "Error while calling enclave function to encrypt transaction.";
                res.status = 500;  // 服务器内部错误
                res.set_content(response_data.dump(), "application/json");
                return;
            }

            // 根据 encrypt_ret 的值判断加密结果
            if (encrypt_ret == 0) {
                std::string warningMsg = getWarningMsg(warning_sign);
                if(warning_sign != TRANSACTION_NO_EXCEPTION) {
                    response_data["transaction_status"] = "Exception";
                    response_data["warning_msg"] = warningMsg;
                    std::cout << "Exception detected: " << warningMsg << std::endl;
                } else {
                    response_data["transaction_status"] = "Success";
                    std::cout << "No exception detected" << std::endl;
                }
                res.status = 200;  // 请求成功
            } else {
                response_data["message"] = "Error while making a warning about transaction.";
                res.status = 400;  // 请求错误
                std::cerr << "Failed to make a warning about transaction." << std::endl;
            }
        } else {
            // 如果缺少必要的字段
            response_data["message"] = "Missing required fields ('from', 'to', 'amount') in the request.";
            res.status = 400;  // 请求错误
            std::cerr << "Missing required fields in the request." << std::endl;
        }
    } catch (const nlohmann::json::exception &e) {
        // 捕获 JSON 解析错误
        response_data["message"] = "Invalid JSON format.";
        res.status = 400;  // 请求错误
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
    } catch (const std::exception &e) {
        // 捕获其他异常
        response_data["message"] = "Internal server error.";
        res.status = 500;  // 服务器内部错误
        std::cerr << "Error: " << e.what() << std::endl;
    }

    // 返回响应
    res.set_content(response_data.dump(), "application/json");
    split_output();
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
 
    /* Utilize edger8r attributes */
    edger8r_array_attributes();
    edger8r_pointer_attributes();
    edger8r_type_attributes();
    edger8r_function_attributes();
    
    /* Utilize trusted libraries */
    ecall_libc_functions();
    ecall_libcxx_functions();
    ecall_thread_functions();
    
    // -------------------------------------------
    // int test_ret = -1;
    // ecall_test_enclave_function(global_eid, &test_ret);

    // Edit here
    httplib::Server svr;

    // 处理 GET 请求
    svr.Get("/", [](const httplib::Request &req, httplib::Response &res) {
        res.set_content("Hello! Use POST to send data.\n", "text/plain");
    });

    // 处理 POST 请求
    svr.Post("/api/add", handle_add_request);
    svr.Post("/api/create_wallet", handle_create_wallet_request);
    svr.Post("/api/shuffle_transaction", handle_deal_transaction_request);
    svr.Post("/api/decrypt_transaction", handle_decrypt_transaction_request);
    svr.Post("/api/encrypt_transaction", handle_encrypt_transaction_request);
    svr.Post("/api/transaction_warning", handle_transaction_warning_request);

    int port = 8082;
    std::cout << "Server is running on http://0.0.0.0:" << port << std::endl;
    split_output();
    svr.listen("0.0.0.0", port);

    // -------------------------------------------
    
    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}

