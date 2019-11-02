
#include <vector>
#include <list>
#include <string>
#include <algorithm>
#include <map>
#include <set>
#include <time.h>
#include <stdio.h>
#include <sstream>
#include <iostream>
#include <iostream>
#include <stdarg.h> 
#include <cstdint>

using namespace std;

#include <capstone/include/capstone/capstone.h>
#include <enma_pe/enma_pe/enma_pe.h>
#include <fukutasm/fukutasm/fukutasm.h>
#include <furikuri/furikuri.h>

int main() {

    pe_image _module(std::string("C:\\test_executable.exe"));

    if (_module.get_image_status() == pe_image_status_unknown) {

        cout << "Cant open file !" << endl;

        return 1;
    }
    else if (_module.get_image_status() == pe_image_status_bad_format) {

        cout << "Target file has invalid pe format !" << endl;

        return 1;
    }


    furikuri fuku;

    if (fuku.set_image_protect(_module)) {

        std::vector<uint8_t> out_image;

        fuku_settings_obfuscation ob_set(2, 2, 40.f, 30.f, 40.f,
            FUKU_ASM_SHORT_CFG_USE_EAX_SHORT | FUKU_ASM_SHORT_CFG_USE_DISP_SHORT | FUKU_ASM_SHORT_CFG_USE_IMM_SHORT, 
            false, false);

        //           { code segment rva, code segment size }
        fuku.add_ob_code_list({ 0x1000 , 0x6F0 }, ob_set);
  
        fuku_settings_mgr fuku_snapshot;

        if (fuku.fuku_protect(out_image)) {

            FILE* hTargetFile;
            fopen_s(&hTargetFile, "C:\\result_executable.exe", "wb");

            if (hTargetFile) {

                fwrite(out_image.data(), out_image.size(), 1, hTargetFile);
                fclose(hTargetFile);

                
                cout << "Protect was successful !" << endl;
            }
        }
        else {
            cout << "Protect was unsuccessful !" << endl;

            return 1;
        }
    }

    return 0;
}
