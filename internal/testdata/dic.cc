__attribute__((noinline)) inline int sw(int i)
{
    switch (i)
    {
    case 0:
        return 3443;
    case 1:
        return 3453;
    case 2:
        return 3353;
    case 3:
        return 4353;
    default:
        return -1;
    }
}

void ref()
{
    sw(2);
}