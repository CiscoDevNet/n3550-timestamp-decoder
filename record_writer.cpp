#include "record_writer.hpp"
#include "record_reader.hpp"
#include "record_process.hpp"
#include "pcap_common.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <stdexcept>
#include <stdio.h>
#include <ctype.h>

struct pcap_writer : public record_writer
{
    const write_options options;
    std::ofstream os;

    pcap_writer(const write_options& opt)
    : options(opt)
    , os(opt.dest, std::ofstream::trunc)
    {
        if (!os.good())
            throw std::invalid_argument(std::string("could not create pcap file"));
        pcap_file_header_t header;
        header.version_major = 2;
        header.version_minor = 4;
        header.linktype = DLT_EN10MB;
        header.magic = (options.write_micros)? pcap_magic_t::micro_magic : pcap_magic_t::nanos_magic;
        header.thiszone = 0;
        header.sigfigs = 0;
        header.snaplen = 0xffff;
        os.write((const char*)&header, sizeof(header));
        if (!os.good())
            throw std::invalid_argument(std::string("could not write to pcap file"));
    }

    std::string type() const override { return "pcap"; }

    int write(const record_time_t& time, const read_record_t& record, const char* buffer)
    {
        if (!os.good())
            return -1;
        if (time.is_keyframe && !options.write_keyframes)
            return +1;

        if (time.hw_time)
        {
            pcap_header_t header;
            header.tv_secs = time.hw_time.sec;
            header.tv_frac = time.hw_time.psec / 1000;
            if (options.write_micros)
                header.tv_frac /= 1000;
            header.len_capture = record.len_capture;
            header.len_orig = record.len_orig;
            os.write((const char*)&header, sizeof(header));
            os.write(buffer, header.len_capture);
        }
        return os.good()? 0 : -1;
    }
};

struct text_writer : public record_writer
{
    const write_options options;
    std::ofstream os;

    text_writer(const write_options& opt)
    : options(opt)
    , os()
    {
        if (options.dest == "-")
            os.open("/dev/stdout");
        else
            os.open(options.dest);
        if (!os.good())
            throw std::invalid_argument(std::string("could not open destination for writing"));
    }

    std::string type() const override { return "text"; }

    void write_time(pstime_t time)
    {
        std::time_t ts = time.sec;
        std::tm tm = *std::localtime(&ts);
        char buffer[128];
        std::size_t written = strftime(buffer, 128, options.text_date_format.c_str(), &tm);
        if (!written)
            throw std::invalid_argument(std::string("bad time format string"));
        os << buffer << '.';
        uint64_t frac = time.psec;
        for (unsigned i = 12; i > time.precision; --i)
            frac /= 10;
        os << std::setfill('0') << std::setw(time.precision) << frac << std::setfill(' ');
        //os << "fracs are "<< frac << std::endl;
    }

    int calc_time_diff(pstime_t new_time, pstime_t prev_time)
    {
        std::time_t new_time_s = new_time.sec;
        std::time_t prev_time_s = prev_time.sec;

	int sec_difference = new_time_s - prev_time_s;
	if(new_time.psec < prev_time.psec)
	{
             int pico_diff = new_time.psec - prev_time.psec;
    	     if(sec_difference >0)
		 return 0;
	     else if(sec_difference == 0)
	     {
		 if(pico_diff < 100000)
	             return 0;
                 os << pico_diff/1000 << " ns" <<std::endl;
	     }
	     else
	     {
    		 os << "seconds off" << std::endl;
                 
	     }
    		 return -1;
        }
	else if(sec_difference < 0)
	{
             if(sec_difference == -1 && prev_time.psec > (10^11))
		  return 0;
	     os << "seconds off" << std::endl;
	     os << "huka" << std::endl;
	     return -1;
	}
	else
	     return 0;
    }

    void write_packet(const char* buffer, size_t len)
    {
        os << std::setfill('0');
        os << std::hex;
        for (size_t i=0; i<len; i+=16)
        {
            size_t next = i+16;
            os << "    ";
            os << std::setw(4) << i << ':';
            for (size_t k=i; k<next; ++k)
            {
                if (k%4 == 0)
                    os << ' ';
                uint8_t c = buffer[k];
                if (k<len)
                    os << std::setw(2) << (int)c;
                else
                    os << "  ";
            }
            os << ' ';
            for (size_t k=i; k<next; ++k)
            {
                if (k%8 == 0)
                    os << ' ';
                char c = buffer[k];
                if (isprint(c))
                    os << c;
                else if (k<len)
                    os << '.';
            }
            os << "\n";
        }
        os << std::dec;
        os.flush();
    }

    int write(const record_time_t& time, const read_record_t& record, const char* buffer)
    {
        if (!os.good())
            return -1;
        if (time.is_keyframe && !options.write_keyframes)
            return +1;
        if (calc_time_diff(time.hw_time, this->prev_time->hw_time) !=0)
        {
            
             write_time(this->prev_time->hw_time);
             if (this->prev_time->device_id != -1 && this->prev_time->port != -1)
             {
                 os << "  (" << std::setfill('0')
                    << std::setw(3) << this->prev_time->device_id
                    << ":"
                    << std::setw(3) << this->prev_time->port
                    << ")" << std::setfill(' ');
             }
            
             os << " " << std::setw(5) << record.len_capture << " bytes" << std::endl;
            
             write_time(time.hw_time);
             if (options.write_clock_times)
             {
                 os << "  (";
                 write_time(record.clock_time);
                 if (time.hw_time && record.clock_time)
                 {
                     pstime_t diff = time.hw_time - record.clock_time;
                     os << std::setprecision(diff.precision) << std::fixed << std::showpos;
                     os << " " << double(diff);
                     os << std::noshowpos;
                 }
                 os << ")";
             }
             if (time.device_id != -1 && time.port != -1)
             {
                 os << "  (" << std::setfill('0')
                    << std::setw(3) << time.device_id
                    << ":"
                    << std::setw(3) << time.port
                    << ")" << std::setfill(' ');
             }
             os << " " << std::setw(5)  << std::endl;
             if (options.write_packet)
                 write_packet(buffer, record.len_capture);
	}

	this->prev_time->hw_time.sec = time.hw_time.sec;
	this->prev_time->hw_time.psec = time.hw_time.psec;
	this->prev_time->hw_time.precision = time.hw_time.precision;
	this->prev_time->device_id = time.device_id;
	this->prev_time->port      = time.port;
        return 0;
    }
};

std::unique_ptr<record_writer> record_writer::pcap(const write_options& opt)
{
    return std::unique_ptr<record_writer>(new pcap_writer(opt));
}

std::unique_ptr<record_writer> record_writer::text(const write_options& opt)
{
    return std::unique_ptr<record_writer>(new text_writer(opt));
}

std::unique_ptr<record_writer> record_writer::make(const write_options& opt) noexcept
{
    try
    {
        /*
         * Choose pcap if the arg ends with standard pcap extention.
         */
        const size_t dst_len = opt.dest.size();
        const bool is_pcap = (dst_len>5 && opt.dest.substr(dst_len-5) == ".pcap");

        if (is_pcap)
            return record_writer::pcap(opt);
        else
            return record_writer::text(opt);
    }
    catch (std::exception& e)
    {
        std::cerr << "Problem creating writer: " << e.what() << std::endl;
        return std::unique_ptr<record_writer>();
    }
}

