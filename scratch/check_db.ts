import { supabase } from '../src/config/supabase';

async function testTelemetry() {
    console.log('Checking telemetry table...');
    
    // Attempt to insert a dummy record
    const dummy = {
        api_access_id: 'b3c55ee4-8360-4ed3-8501-4340be175099',
        target: '8.8.8.8',
        verdict: 'TRUSTED',
        trust_score: 100,
        profile: 'api',
        latency_ms: 10,
        reason: 'test_insert',
        confidence: 0.99,
        bwt_verified: false,
        created_at: new Date().toISOString()
    };
    
    console.log('Attempting dummy insert...');
    try {
        const { error: insertError } = await supabase.from('telemetry').insert([dummy]);
        
        if (insertError) {
            console.error('INSERT ERROR:', insertError.message);
            console.error('Details:', insertError.details);
            console.error('Hint:', insertError.hint);
        } else {
            console.log('INSERT SUCCESS!');
        }
    } catch (e: any) {
        console.error('EXCEPTION:', e.message);
    }

    console.log('Querying telemetry again...');
    const { data, error } = await supabase.from('telemetry').select('*').limit(1);
    if (error) {
        console.error('Query error:', error.message);
    } else {
        console.log('Data found:', data);
    }
}

testTelemetry();
