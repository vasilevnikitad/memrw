#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace std::literals::string_literals;

struct parameters {
public:
    using value_type = std::uint32_t;

    enum class action {
        read,
        write,
        show_help,
    };

    static std::string get_help() {
        static std::string const help{
            program_name + " - reads/writes to /dev/mem\n"s
            "Usage:\n"
            + " " + program_name + " <ADDRESS>        \t\tread unsigned 32-bits value from address and print output in hex base.\n"
            + " " + program_name + " <ADDRESS> <VALUE>\t\twrite unsigned 32-bits value to address."
        };

        return help;
    }

    value_type* get_address() const {
        return address;
    }

    value_type get_value() const {
        return value;
    }

    action get_action() const {
        return action;
    }

    parameters(int argc, char const* argv[]) {
        using address_t = std::decay_t<decltype(address)>;
        using value_t = std::decay_t<decltype(value)>;

        constexpr static int address_pos{1};
        constexpr static int value_pos{2};

        switch (argc) {
            case 2:
                action = action::read;
                address = reinterpret_cast<address_t>(get_int_type_from_str<std::size_t>(argv[address_pos]));
                break;
            case 3:
                action = action::write;
                address = reinterpret_cast<address_t>(get_int_type_from_str<std::size_t>(argv[address_pos]));
                value = get_int_type_from_str<value_t>(argv[value_pos]);
                break;
            default:
                action = action::show_help;
                break;
        }
    }

private:
    template<typename T = unsigned long long>
    static T get_int_type_from_str(char const* line)
    requires (std::is_convertible_v<decltype(std::stoull(line, nullptr, 0)), T>) {
            try {
                // std::stoull returns not a pretty message in case of exception.
                // that's why there is a try{} catch{}  block.
                return static_cast<T>(std::stoull(line, nullptr, 0));
            } catch (std::invalid_argument const&) {
                throw std::invalid_argument{"Invalid argument"};
            } catch (std::out_of_range const&) {
                throw std::out_of_range{"Value is out of range"};
            }
    }

    value_type *address{nullptr};
    value_type value;
    action action;
    static constexpr auto program_name{"memrw"};
};

class mem {
public:
    mem() {
        if ((fd = open(dev_mem_file, O_RDWR | O_SYNC)) < 0)
            throw std::system_error{errno, std::system_category(), "Failed to open"s + dev_mem_file};
    }

    template<typename T>
    T read(T const* const addr) {
        std::size_t const page_aligned_off(reinterpret_cast<std::size_t>(addr) & ~page_mask);
        T const* const offset_addr{reinterpret_cast<T const*>(reinterpret_cast<std::size_t>(addr) & page_mask)};

        return mem_map{fd, page_aligned_off, sizeof(T)}.read(offset_addr);
    }

    template<typename T>
    void write(T* const addr, T const& value) {
        std::size_t const page_aligned_off(reinterpret_cast<std::size_t>(addr) & ~page_mask);
        T* const offset_addr{reinterpret_cast<T*>(reinterpret_cast<std::size_t>(addr) & page_mask)};

        mem_map{fd, page_aligned_off, sizeof(T)}.write(offset_addr, value);
    }

    ~mem() try {
        if (close(fd) < 0)
            throw std::system_error{errno, std::system_category(), "Failed to close"s + dev_mem_file};
    } catch(std::exception const& e) {
        std::cerr << "Failed to destroy mem class :" << e.what() << std::endl;
    }

private:
    int fd;
    static constexpr auto dev_mem_file{"/dev/mem"};

    std::size_t const page_sz{static_cast<std::size_t>(sysconf(_SC_PAGESIZE))};
    std::size_t const page_mask{page_sz - 1};

    struct mem_map {
        mem_map(int const fd, std::size_t const offset_page_aligned, std::size_t const sz) : map_size{sz} {
            mmap_addr = mmap(nullptr, sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, offset_page_aligned);

            if (mmap_addr == MAP_FAILED)
                throw std::system_error{errno, std::system_category(), "Failed to map memory"};
        }

        template<typename T>
        T read(T const* const addr) {
            return *get_offset(addr);
        }

        template<typename T>
        void write(T* const addr, T const& value) {
            *get_offset(addr) = value;
        }

        ~mem_map() noexcept(false) {
            if (munmap(mmap_addr, map_size) < 0)
                throw std::system_error{errno, std::system_category(), "Failed to unmap memory"};
        }

        void* mmap_addr;
        std::size_t const map_size;

    private:
        template<typename T>
        T* get_offset(T* const addr) {
            auto const mmap_addr_byte{reinterpret_cast<std::byte*>(mmap_addr)};
            auto const addr_byte{reinterpret_cast<off_t>(addr)};
            return reinterpret_cast<T*>(mmap_addr_byte + addr_byte);
        }
    };
};

int main(int argc, char const* argv[]) try {
    parameters params{argc, argv};

    switch (params.get_action()) {
        case  parameters::action::read: {
            std::cout << "0x" << std::hex << mem{}.read(params.get_address()) << std::endl;
            break;
        }
        case parameters::action::write: {
            mem{}.write(params.get_address(), params.get_value());
            break;
        }

        case parameters::action::show_help: {
            std::cout << parameters::get_help() << std::endl;
            break;
        }

        default:
            throw std::logic_error{"unsupported parameter action"};
    }

    return EXIT_SUCCESS;
} catch (std::exception const& e) {
    std::cerr << e.what() << std::endl;
    std::cout << parameters::get_help() << std::endl;
    return EXIT_FAILURE;
} catch (...) {
    std::cerr << "Unknown exception" << std::endl;
    std::cout << parameters::get_help() << std::endl;
    return EXIT_FAILURE;
}
