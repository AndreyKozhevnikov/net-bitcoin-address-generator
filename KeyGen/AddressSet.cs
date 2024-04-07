using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KeyGenNameSpace {
    public class AddressSet {
        public AddressSet() {
            Addresses = new List<string>();
        }
        public string PrivateKey { get; set; }
        public string WIF { get; set; }

        public List<string> Addresses { get; set; }
    }
}
