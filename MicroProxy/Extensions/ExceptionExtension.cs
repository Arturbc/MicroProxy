using MicroProxy.Extensions;
using System.Diagnostics;

namespace MicroProxy.Extensions
{
    public static class ExceptionExtension
    {
        [DebuggerNonUserCode]
        public static bool Contains(this Exception ex, Type type) => Contains(ex, [type]);

        public static bool Contains(this Exception ex, Type[] types)
        {
            bool resultado = false;

            while (ex != null)
            {
                resultado = types.Contains(ex.GetType());
                if (resultado) { return resultado; }
                ex = ex.InnerException!;
            }

            return resultado;
        }
    }
}
