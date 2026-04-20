const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

async function test() {
    const { data } = await supabase.from('user_policies').select('*').eq('user_id', 'fe0dafa1-8463-4232-852a-8e545dd5a5cd');
    console.log("user_policies result:", data);
}
test();
