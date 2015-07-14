/*
 * cryptor.h
 *
 *  Created on: 2. tra 2015.
 *      Author: Zdravko
 */

#ifndef CRYPTOR_H_
#define CRYPTOR_H_

// UTILITY function
// For generating UUID V1
std::string uuidKey()
{
	//generating
	boost::uuids::uuid uuid; // instance
	uuid.data[6]=0x10; // changes version type in the octet9 to ver 1 (time based)
	uuid = boost::uuids::random_generator()(); //generate UUID in HEX form with dashes
	// conversion from boost UUID format to string
	std::string uuidString = boost::uuids::to_string(uuid);
	// remove dashes from string UUID
	uuidString.erase (std::remove(uuidString.begin(), uuidString.end(), '-'), uuidString.end());
	// to lowercase (because of converting to hex, standalone lookup is lowercase)
	std::transform(uuidString.begin(), uuidString.end(), uuidString.begin(), ::tolower);

	return uuidString;
}

// UTILITY function
// For converting HEX string to CHAR string
std::string hexToString(const std::string& input)
{
    static const char* const lut = "0123456789abcdef";
    size_t len = input.length();
    if (len & 1) throw std::invalid_argument("odd length");

    std::string output;
    output.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2)
    {
        char a = input[i];
        const char* p = std::lower_bound(lut, lut + 16, a);
//        if (*p != a) throw std::invalid_argument("not a hex digit");

        char b = input[i + 1];
        const char* q = std::lower_bound(lut, lut + 16, b);
//        if (*q != b) throw std::invalid_argument("not a hex digit");

        output.push_back(((p - lut) << 4) | (q - lut));
    }
    return output;
}

// UTILITY function
// For converting CHAR string to HEX string
std::string stringToHex(const std::string& input)
{
    static const char* const lut = "0123456789abcdef";
    size_t len = input.length();

    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

// UTILITY function
// A simple hex-print routine.
// Could be modified to print 16 bytes-per-line
// Modified to also return a string equivalent
static std::string hex_print(const void* pv, size_t len)
{
	/*STRING*/ std::string output;
    const unsigned char * p = (const unsigned char*)pv;
    if (NULL == pv)
    {
        printf("NULL");
    }
    else
    {
        size_t i = 0;
        for (; i<len;++i)
        {
            printf("%02X ", *p++);
        }
    }
    printf("\n");
    return output = std::string(reinterpret_cast<const char*>(p));
}

#endif /* CRYPTOR_H_ */
