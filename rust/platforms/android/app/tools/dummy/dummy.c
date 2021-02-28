// In CMakeLists.txt unless we do an add_dependencies(libdummy.so libnxt-go.so),
// the darn thing doesnt compile and craps out saying some command_logs.json not
// generated etc.. So just to get a dependency added, here is a dummy lib
int main(int argc, char *argv[])
{
    return 0;
}
