///////////////////////////////////////////////////////////
//  DataAccumulator.cpp
//  Implementation of the Class DataAccumulator
//  Created on:      03-мар-2015 12:11:53
//  Original author: user1
///////////////////////////////////////////////////////////

#include "common.h"
#include "DataAccumulator.h"
#include "NetStat.h"
#include <stdexcept>

#include <set>
#include <fstream>
#include <iterator>
#include <algorithm>
#include <boost/lexical_cast.hpp>
#include <boost/thread.hpp>
#include <thread>
#include <chrono>
#include <exception>
#include <mutex>
#include "Log.h"

#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_QUEUE_SIZE      1000        // максимальное кол-во запросов на обработку io_service
                                        // в противном случае будет большое потребление памяти
extern bool g_debug;

DataAccumulator::DataAccumulator()
    : m_mode(wmode_learning),
      m_work( m_ioService ), m_countProcess(0), m_maxParameterId(0)
{
    m_analizers.resize(PROTOCOL_END);
    m_analizers[PROTOCOL_HTTP] = std::make_shared<StatisticalAnalyzer>();
    m_analizers[PROTOCOL_FTP]  = std::make_shared<StatisticalAnalyzer>();
    m_analizers[PROTOCOL_SMTP] = std::make_shared<StatisticalAnalyzer>();
    m_analizers[PROTOCOL_POP3] = std::make_shared<StatisticalAnalyzer>();
    m_tables.resize(PROTOCOL_END);

}

DataAccumulator::~DataAccumulator(){
}

void DataAccumulator::print_tables()
{
    std::ofstream ofs;
    ofs.open("tables.txt", std::ofstream::out);

    for (int i = 0; i < PROTOCOL_END; ++i)
    {
        std::string type;
        auto& tableType =  m_tables[i];
        switch ( i ) {
        case PROTOCOL_HTTP: type = "PROTOCOL_HTTP";   break;
        case PROTOCOL_POP3: type = "PROTOCOL_POP3";   break;
        case PROTOCOL_SMTP: type = "PROTOCOL_SMTP";   break;
        case PROTOCOL_FTP:  type = "PROTOCOL_FTP";    break;
        }
        ofs << "\nTables " << type << "\n";
        for (auto& table: tableType)
            ofs <<table.m_id << "\t" << table.m_maxIntrpValue[0] << "\t" << table.m_maxIntrpValue[1] << "\t" << table.m_nameString.first << ":"<< table.m_nameString.second << "\n";
        ofs << "Count tables of type " << type << " is " << tableType.size() <<"\n";
    }
    ofs.flush();
    ofs.close();
}


void DataAccumulator::fillTables(LerningResult& result, PROTOCOL_TYPE protocol)
{
    std::map<PROTOCOL_TYPE, std::set<ParameterType>>  intersection;
    // таблицы пересечений для http строятся из параметров сетевых, html, http, но не из ftp...
    intersection[PROTOCOL_HTTP].insert(PT_NET);
    intersection[PROTOCOL_HTTP].insert(PT_HTML);
    intersection[PROTOCOL_HTTP].insert(PT_HTTP);
    intersection[PROTOCOL_HTTP].insert(PT_HTTP_CLIENT);
    intersection[PROTOCOL_HTTP].insert(PT_HTTP_SERVER);

    intersection[PROTOCOL_FTP].insert(PT_NET);
    intersection[PROTOCOL_FTP].insert(PT_FTP_SERVER);
    intersection[PROTOCOL_FTP].insert(PT_FTP_CLIENT);

    intersection[PROTOCOL_POP3].insert(PT_NET);
    intersection[PROTOCOL_POP3].insert(PT_POP3_CLIENT);
    intersection[PROTOCOL_POP3].insert(PT_POP3_SERVER);

    intersection[PROTOCOL_SMTP].insert(PT_NET);
    intersection[PROTOCOL_SMTP].insert(PT_SMTP_CLIENT);
    intersection[PROTOCOL_SMTP].insert(PT_SMTP_SERVER);
    std::vector<int> id;
    m_tables[protocol].clear();

    auto intersection_param = intersection[protocol];
    for ( auto &p: result )
    {
        if ( intersection_param.find(p.second.type) != intersection_param.end())
        {
            id.push_back(p.first);
        }
        if ( m_maxParameterId < static_cast<unsigned int>(p.first))
            m_maxParameterId = p.first;
    }
    size_t size = id.size();
    m_learningResult = result;
    for ( size_t i = 0; i < size; ++i )
    {
        for ( size_t j = i + 1; j < size; ++j )
        {
            TableData data;
            std::pair<int,int> p(id[i],id[j]);  // все сочетания
            AccumulatorTable anal;
            anal.m_name = p;
            LerningResultData& resultData1 = result[id[i]];
            LerningResultData& resultData2 = result[id[j]];
            anal.m_nameString = std::pair<std::string, std::string>(resultData1.name,
                                                                    resultData2.name);
            anal.m_id = id[i] | (id[j] << 16);
            anal.m_maxIntrpValue[0] = resultData1.maxInterpValue;
            anal.m_maxIntrpValue[1] = resultData2.maxInterpValue;
            m_tables[protocol].push_back( anal );
            m_result_template[protocol][anal.m_id];
        }
    }
    if ( m_mode == wmode_learning  || WORK_MODE(m_mode) )
    {
        // передадим в анализатор максимальные значения параметров
        boost::unordered_map<TableName, std::pair<uint64_t, uint64_t>> maxValues;
        for ( auto & table: m_tables[protocol] )
        {
            maxValues[table.m_id] = std::pair<uint64_t, uint64_t>(table.m_maxIntrpValue[0], table.m_maxIntrpValue[1] );
        }
        m_analizers[protocol]->SetMaxTableValues(maxValues);   // нужно вызывать в режиме обучения
    }
}

void DataAccumulator::update_params(LerningResult& result)
{
    // В result все параметры полученные при обучении.
    // Нужно разделить параметры по анализируемым протоколам.
    // Т.е. когда будем строить пересечение таблиц, ftp не должно пересекаться с http
    for (int i = 0; i < PROTOCOL_END; ++i)
        m_result_template[i].clear();

    fillTables(result, PROTOCOL_HTTP);
    fillTables(result, PROTOCOL_POP3);
    fillTables(result, PROTOCOL_SMTP);
    fillTables(result, PROTOCOL_FTP);

#if 1
    if ( g_debug )
        print_tables();
#endif
}


void DataAccumulator::update_config(Config &config)
{
    m_config = config.accumulator;
    if (!m_config.threads)
        m_config.threads = boost::thread::hardware_concurrency();
}

std::string DataAccumulator::table_name_from_id(int id)
{
    int p1 = id & 0xFFFF;
    int p2 = id >> 16;

    return m_learningResult[p1].name + ":" + m_learningResult[p2].name;
}

void DataAccumulator::param_id_from_table_id(int id_table, int& param_id_1, int & param_id_2)
{
    param_id_1 = id_table & 0xFFFF;
    param_id_2 = id_table >> 16;
}
#if 0
std::ofstream ofs;

void save_result_to_file(TablesData& result)
{
    static int n_session = 0;

    if ( !n_session )
    {
        ofs.open("result.txt", std::ofstream::out);

    }

    for (auto & table: result)
    {
        OneTableData& tab = table.second;
        for (auto & data: tab)
        {
            if (table.first < 4000000 )
                ofs << n_session << "\t" << table.first << "\t" << (int32_t)data.first.first << "\t" << (int32_t)data.first.second << "\t" <<  data.second << "\n";
        }
    }
    ofs.flush();
    ++n_session;
}
#endif

int DataAccumulator::session_end(const SessionInfoPtr& info)
{
    ++m_countProcess;
    if ( m_config.threads == -1 )
    {
        if ( process_session_end(info) )
            return NET_STAT_ANOMALY;
        else
            return NET_STAT_OK;
    }
    else
    {
        while ( m_countProcess > MAX_QUEUE_SIZE )
        {
            // wait for process queue io_service
            std::this_thread::sleep_for(std::chrono::seconds(1));
#if 0
            std::cout << " Wait for process queue\n";
#endif
        }
        m_ioService.post( boost::bind( &DataAccumulator::process_session_end, this, info ) );
        return NET_STAT_WAIT;
    }
}

int DataAccumulator::process_session_end(const SessionInfoPtr& info)
{
    auto& store = info->accumulator.store;
    TablesData result = m_result_template[info->protocol];  //  std::map<std::pair<int,int>, OneTableData >

    // для ускорения поиска параметров в результатах интепретатора,
    // скопируем результаты в vector
    std::vector<std::vector<std::list<TableValue>>> vector_store(store.size());
    // первый вектор - запрос/ответы
    // второй - id параметра (тега)
    // лист - значения тега
    int i = 0;
    for ( auto &data: store )
    {
        std::vector<std::list<TableValue>>& store_n = vector_store[i++];
        store_n.resize(m_maxParameterId + 1);
        for (auto& id: data)
            store_n[id.first] = id.second;
        for (auto& values: store_n)
            if ( !values.size() )
                values.push_back(-1);       // -1 - значение отсутствует, такого параметра нет в сессии
    }
    for ( auto & table: m_tables[info->protocol] )    // таблицы
    {
        int table_name = table.m_id;
        OneTableData& one_table = result[table_name];
        auto id_1 = table.m_name.first;
        auto id_2 = table.m_name.second;

        for ( auto & data: vector_store )    // цикл по пакетам (запрос+ответ)
        {
            auto& param_1 = data[id_1];      // ищем в результатах первый параметр
            auto& param_2 = data[id_2];
            for ( auto value_1 : param_1 )
                for ( auto value_2 : param_2 )
                {
                    std::pair<TableValue,TableValue> value(value_1, value_2);
                    ++one_table[value];
                }
        }
    }  
    StatAnalyzerResult r;

    bool res = m_analizers[info->protocol]->StatAdd(result, r);
#if 0
    save_result_to_file(result);
#endif

#if 1

    if ( res )
    {
        std::map<int, int> parameters_ex;   // превышение значений
        std::map<int, int> parameters_new;  // новые значения

        std::lock_guard<std::mutex> lock(m_logMutex);
        ++m_count_yes;

        logger << "Session has anomaly: \n";
        struct in_addr ip_addr;
        ip_addr.s_addr = info->tcp.daddr;
        logger << "\t dst  " << inet_ntoa(ip_addr) << "\n";
        ip_addr.s_addr = info->tcp.saddr;
        logger << "\t src  " << inet_ntoa(ip_addr) << "\n";
        logger << "\t port_dst  " << info->tcp.source << "\n";
        logger << "\t port_src  " << info->tcp.dest << "\n" ;

        for (auto it: r.m_result)
        {         
            int param_id_1,param_id_2;
            param_id_from_table_id(it.m_id, param_id_1, param_id_2);
            if ( it.m_reason == reason_excess )
            {
                ++parameters_ex[param_id_1];
                ++parameters_ex[param_id_2];
            } else if ( it.m_reason == reason_newvalue )
            {
                ++parameters_new[param_id_1];
                ++parameters_new[param_id_2];
            }
        }

        bool first = true;
        if ( parameters_new.size() )
        {
            logger << "\t New param : ";
            for (auto& it: parameters_new)
            {
                if ( first )
                    first = false;
                else
                    logger << ", ";
                logger << m_learningResult[it.first].name;
            }
            logger << "\n";
        }

        first = true;
        if ( parameters_ex.size() )
        {
            logger << "\t Excess param : ";
            for (auto& it: parameters_ex)
            {
                if ( first )
                    first = false;
                else
                    logger << ", ";
                logger << m_learningResult[it.first].name;
            }
            logger << "\n";
        }
        logger << "\n";
        logger.flush();
    }
    else
    {
        ++m_count_no;
    }
#endif

    --m_countProcess;
    if ( m_config.threads != -1 )
        async_result(info, res?NET_STAT_ANOMALY:NET_STAT_OK);
    return res?NET_STAT_ANOMALY:NET_STAT_OK;
}

ANALIZER_RESULT DataAccumulator::story_data(SessionInfoPtr& session, InterreterResult &data)
{     
    // собираем интепретированные пакеты до конца сессии
    auto& store =  session->accumulator.store;
#if 0       // реализация в proxy
    // для не-хттп сессия будем все данные записывать в один запрос/ответ
    if ( session->protocol != PROTOCOL_HTTP && store.size() )
        store.front().insert(data.begin(), data.end());
    else
#endif
        store.push_back(data);
    return AN_OK;
}

void DataAccumulator::start(workmode mode)
{   
    m_mode = mode;
    if ( m_mode == wmode_learning ||
         WORK_MODE(m_mode) )
    {
        // TODO: сделать дообучение анализатора
        bool import = m_analizers[PROTOCOL_HTTP]->ImportLearningTables(m_config.httpPath);
        import = import || m_analizers[PROTOCOL_FTP]->ImportLearningTables(m_config.ftpPath);
        import = import || m_analizers[PROTOCOL_POP3]->ImportLearningTables(m_config.pop3Path);
        import = import || m_analizers[PROTOCOL_SMTP]->ImportLearningTables(m_config.smtpPath);
        if ( !import && WORK_MODE(m_mode) )
            throw std::runtime_error("No learning data");
        StatisticalAnalyzer::statmode mode = m_mode==wmode_learning?StatisticalAnalyzer::statmode_learning:StatisticalAnalyzer::statmode_work;
        for ( auto& analizer: m_analizers )
            analizer->ChangeMode(mode);
        startIoService();
    }    
    logger << "Number threads is  " << m_config.threads << "\n";
    m_countProcess = 0;    
}

void DataAccumulator::stop()
{
#if 0
    ofs.close();
#endif
    if ( m_countProcess != 0 )
        std::cout << "Waiting processing (it may take a few seconds/minutes) ..." << std::endl;

    while ( m_countProcess != 0 )
    {        
        std::this_thread::sleep_for(std::chrono::seconds(1));
#if 0
        std::cout << "queule : " << m_countProcess << std::endl;
#endif
    }
    auto count_all = m_count_yes + m_count_no;
    logger << "Count anomaly session is " << m_count_yes << " ( " << m_count_yes*100.0/ (count_all?count_all:1) << "% ) from " << m_count_yes + m_count_no << "\n";
    if ( m_mode == wmode_learning )
    {
        for (auto& analyzer: m_analizers )
            analyzer->ChangeMode(StatisticalAnalyzer::statmode_work); // чтобы Анализатор сгенерировал данные обучения
        m_analizers[PROTOCOL_HTTP]->ExportLearningTables(m_config.httpPath);
        m_analizers[PROTOCOL_FTP]->ExportLearningTables(m_config.ftpPath);
        m_analizers[PROTOCOL_POP3]->ExportLearningTables(m_config.pop3Path);
        m_analizers[PROTOCOL_SMTP]->ExportLearningTables(m_config.smtpPath);
    }
}

void DataAccumulator::OnEvent(int)
{

}

void DataAccumulator::OnSerialize(const char* data, size_t len)
{

}

void DataAccumulator::startIoService() {
    if ( m_config.threads == -1 )
        return;
    for ( int i = 0; i < m_config.threads ; ++i ) {
        boost::thread t( &DataAccumulator::runIoService, this );
    }
}

void DataAccumulator::runIoService() {
    try {
        m_ioService.run();
    }
    catch ( std::exception& e ) {
        std::cerr << "DataAccumulator::runIoService exception caught: " << e.what() << std::endl;
    }
}

