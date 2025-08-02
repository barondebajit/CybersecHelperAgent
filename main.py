import os
import dotenv
from colorama import Fore, Style
from google import genai
from google.genai import types

from helper.dns import (
    dns_lookup, reverse_dns_lookup, blacklist_check,
    dns_lookup_function, reverse_dns_lookup_function, blacklist_check_function
)

from helper.file_metadata import (
    extract_file_metadata, extract_multiple_files_metadata, calculate_file_hashes,
    get_file_basic_info, detect_file_type_signature,
    extract_metadata_function, extract_multiple_function, calculate_hashes_function,
    basic_info_function, detect_type_function
)

from helper.network_scanner import (
    scan_target_ports, scan_single_port, scan_port_range, scan_common_ports,
    resolve_target_hostname, detect_target_os,
    scan_ports_function, scan_single_port_function, scan_range_function,
    scan_common_function, resolve_hostname_function, detect_os_function
)

from helper.pii_detector import (
    scan_text_for_pii, scan_file_for_pii, scan_directory_for_pii,
    generate_pii_report, save_pii_results, validate_ssn_number,
    validate_credit_card_number, validate_aadhar_number, validate_indian_phone_number,
    scan_text_function, scan_file_function, scan_directory_function,
    generate_report_function, save_results_function, validate_ssn_function,
    validate_credit_card_function, validate_aadhar_function, validate_phone_function
)

dotenv.load_dotenv()
gemini_api_key = os.getenv("GEMINI_API_KEY")

client = genai.Client(api_key=gemini_api_key)
tools = [types.Tool(function_declarations=[
    dns_lookup_function,
    reverse_dns_lookup_function,
    blacklist_check_function,
    extract_metadata_function,
    extract_multiple_function,
    calculate_hashes_function,
    basic_info_function,
    detect_type_function,
    scan_ports_function,
    scan_single_port_function,
    scan_range_function,
    scan_common_function,
    resolve_hostname_function,
    detect_os_function,
    scan_text_function,
    scan_file_function,
    scan_directory_function,
    generate_report_function,
    save_results_function,
    validate_ssn_function,
    validate_credit_card_function,
    validate_aadhar_function,
    validate_phone_function
])]
config = types.GenerateContentConfig(tools=tools)

def handle_function_call(function_call):
    function_map = {
        "dns_lookup": dns_lookup,
        "reverse_dns_lookup": reverse_dns_lookup,
        "blacklist_check": blacklist_check,
        "extract_file_metadata": extract_file_metadata,
        "extract_multiple_files_metadata": extract_multiple_files_metadata,
        "calculate_file_hashes": calculate_file_hashes,
        "get_file_basic_info": get_file_basic_info,
        "detect_file_type_signature": detect_file_type_signature,
        "scan_target_ports": scan_target_ports,
        "scan_single_port": scan_single_port,
        "scan_port_range": scan_port_range,
        "scan_common_ports": scan_common_ports,
        "resolve_target_hostname": resolve_target_hostname,
        "detect_target_os": detect_target_os,
        "scan_text_for_pii": scan_text_for_pii,
        "scan_file_for_pii": scan_file_for_pii,
        "scan_directory_for_pii": scan_directory_for_pii,
        "generate_pii_report": generate_pii_report,
        "save_pii_results": save_pii_results,
        "validate_ssn_number": validate_ssn_number,
        "validate_credit_card_number": validate_credit_card_number,
        "validate_aadhar_number": validate_aadhar_number,
        "validate_indian_phone_number": validate_indian_phone_number
    }
    
    if function_call.name in function_map:
        result = function_map[function_call.name](**function_call.args)
        
        if isinstance(result, str):
            return {"result": result}
        elif isinstance(result, bool):
            return {"result": result}
        elif result is None:
            return {"result": None, "error": "No result found"}
        else:
            return result
    else:
        return {"error": "Unknown function"}

def chat_with_agent(user_message):
    response = client.models.generate_content(
        model="gemini-1.5-flash",
        contents=user_message,
        config=config
    )
    
    if response.candidates[0].content.parts[0].function_call:
        function_call = response.candidates[0].content.parts[0].function_call
        
        print(Fore.YELLOW+f"\nFunction to call: {function_call.name}"+Fore.RESET)
        print(Fore.LIGHTBLUE_EX+f"Arguments: {function_call.args}"+Fore.RESET)

        result = handle_function_call(function_call)
        print(Fore.GREEN+f"Function completed"+Fore.RESET)
        
        function_response_part = types.Part(
            function_response=types.FunctionResponse(
                name=function_call.name,
                response=result
            )
        )
        
        conversation = [
            types.Content(role="user", parts=[types.Part(text=user_message)]),
            types.Content(role="model", parts=[response.candidates[0].content.parts[0]]),
            types.Content(role="user", parts=[function_response_part])
        ]
        
        follow_up = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=conversation,
            config=config
        )
        print(Fore.MAGENTA+f"\nFinal response: {follow_up.text}"+Fore.RESET)
        return follow_up.text
    else:
        print(Fore.GREEN+f"Direct response: {response.text}"+Fore.RESET)
        return response.text

if __name__ == "__main__":
    print(Fore.CYAN+"Multi-Tool Security Agent Ready!")
    print("\nDNS Functions: dns_lookup, reverse_dns_lookup, blacklist_check")
    print("File Metadata Functions: extract_file_metadata, extract_multiple_files_metadata, calculate_file_hashes, get_file_basic_info, detect_file_type_signature")
    print("Network Scanner Functions: scan_target_ports, scan_single_port, scan_port_range, scan_common_ports, resolve_target_hostname, detect_target_os")
    print("PII Scanner Functions: scan_text_for_pii, scan_file_for_pii, scan_directory_for_pii, generate_pii_report, save_pii_results")
    print("Validation Functions: validate_ssn_number, validate_credit_card_number, validate_aadhar_number, validate_indian_phone_number"+Fore.RESET)
    
    while True:
        user_input = input("\nEnter your query (or 'quit' to exit): ")
        if user_input.lower() == 'quit':
            break
        
        try:
            chat_with_agent(user_input)
        except Exception as e:
            print(f"Error: {e}")