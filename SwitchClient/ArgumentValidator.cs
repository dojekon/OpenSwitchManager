using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SwitchClient {
    public static class ArgumentValidator {
        public static void ValidateNotNullOrEmpty(params (string Name, object? Value)[] args) {
            foreach (var (name, value) in args) {
                switch (value) {
                    case null:
                        throw new ArgumentNullException(name);
                    case string s when string.IsNullOrWhiteSpace(s):
                        throw new ArgumentNullException("Arg cant me empty string", name);
                    case ICollection<object> c when c.Count == 0:
                        throw new ArgumentNullException("Collection cannot be empty", name);
                }
            }
        }
    }
}
