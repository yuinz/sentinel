require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

async function checkColumn() {
    const { data, error } = await supabase.from('site_visits').select('path').limit(1);
    if (error) {
        console.log("COLUMN_DOES_NOT_EXIST");
    } else {
        console.log("COLUMN_EXISTS");
    }
}
checkColumn();
