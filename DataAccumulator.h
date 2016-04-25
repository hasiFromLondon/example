#if !defined(EA_3D6820FF_8AE8_4b16_B574_0AC0A901663C__INCLUDED_)
#define EA_3D6820FF_8AE8_4b16_B574_0AC0A901663C__INCLUDED_
#include "common.h"
#include "NetData.h"
#include <memory>
#include <list>
#include <nids.h>   // for tuple4*
#include "statisticalanalyzer.h"

#include <boost/asio.hpp>
#include <atomic>

/**
 * Модуль производит сохранение всех параметров единого набора данных в
 * оптимизированном для последующей обработки формате.
 * Например при передаче документа HTML, модуль произведет необходимый парсинг
 * последнего и сохранит не только интерпретации определенных тегов, но и сетевые
 * атрибуты документа (порты, адреса которые использовались на этапе получения
 * данных)
 * На первом этапе реализации сохранение производится в формате std::unordered_map,
 * std::map
 */

//интерфейс
class IEventProcessor
{
public:
  virtual void OnEvent(int) = 0;
  virtual void OnSerialize(const char* data, size_t len) = 0;
};

class DataAccumulator: public IEventProcessor
{
    typedef struct
    {
        std::map<std::pair<TableValue,TableValue>, int >  table;
    } TableData;

    struct AccumulatorTable
    {
        std::pair<int,int>  m_name;
        std::pair<std::string,std::string>  m_nameString;
        TableData           m_data;
        int                 m_id;
        int                 m_maxIntrpValue[2];
    };

public:
	DataAccumulator();
	virtual ~DataAccumulator();

protected:
    ANALIZER_RESULT story_data(SessionInfoPtr &session, InterreterResult& data);
    int session_end(const SessionInfoPtr &info);
    void update_config(Config &params);
    void update_params(LerningResult&);     // сообщает по каким параметрам строить таблицы
    ANALIZER_RESULT print_data( );
    void OnEvent(int) override;
    void OnSerialize(const char* data, size_t len) override;

    void start(workmode mode);
    void stop(); 
    std::string table_name_from_id(int id);
    void print_tables();
    void param_id_from_table_id(int id_table, int& param_id_1, int & param_id_2);
    void runIoService();
    void startIoService();
    int  process_session_end(const SessionInfoPtr& info);
    virtual void async_result(const SessionInfoPtr& info, int res) {};
    void fillTables(LerningResult &result, PROTOCOL_TYPE protocol);
protected:

    std::vector<std::vector<AccumulatorTable>>         m_tables;
    std::vector<std::shared_ptr<StatisticalAnalyzer> > m_analizers;
    workmode                   m_mode;
    AccumulatorConfig          m_config;
    TablesData                 m_result_template[PROTOCOL_END];   // только для ускорения
    LerningResult              m_learningResult;
    boost::asio::io_service        m_ioService;
    boost::asio::io_service::work  m_work;   
    std::atomic_ulong          m_countProcess;
    std::mutex                 m_logMutex;
    std::atomic_ulong          m_count_yes;
    std::atomic_ulong          m_count_no;
    unsigned int               m_maxParameterId;

};
#endif // !defined(EA_3D6820FF_8AE8_4b16_B574_0AC0A901663C__INCLUDED_)
