# 关于ChatGLM2-6B训练的问题



## 主要问题

使用默认的脚本对ChatGLM2-6B模型进行训练后报错，暂时没有找到解决办法。



## 详细描述：

- 环境：如下所示。使用该环境在10月22日已经完成过一次训练，所以应该不是环境的问题。

  ![image-20231026191738014](C:\Users\Icarus\AppData\Roaming\Typora\typora-user-images\image-20231026191738014.png)

- 脚本：位于`/media/hnu/hnu2023/huangzhan/ChatGLM2-6B/ptuning/test.sh`，内容如下：

  ```
  PRE_SEQ_LEN=128
  LR=2e-2	# 学习率
  NUM_GPUS=1	# gpu数量
  
  torchrun --standalone --nnodes=1 --nproc-per-node=$NUM_GPUS main.py \
      --do_train \
      --train_file /media/hnu/hnu2023/huangzhan/training/datax.jso \
      --validation_file /media/hnu/hnu2023/huangzhan/training/devx.json \
      --preprocessing_num_workers 10 \
      --prompt_column content \
      --response_column summary \
      --overwrite_cache \
      --model_name_or_path /media/hnu/hnu2023/huangzhan/chatglm2-6b \
      --output_dir /media/hnu/hnu2023/huangzhan/training/output2 \
      --overwrite_output_dir \
      --max_source_length 64 \
      --max_target_length 128 \
      --per_device_train_batch_size 1 \
      --per_device_eval_batch_size 1 \
      --gradient_accumulation_steps 16 \
      --predict_with_generate \
      --max_steps 3000 \
      --logging_steps 10 \
      --save_steps 1000 \
      --learning_rate $LR \
      --pre_seq_len $PRE_SEQ_LEN \
      --quantization_bit 4
  ```

  --train_file，--validation_file，--model_name_or_path，--output_dir分别标识了训练数据集、验证数据集、模型、输出文件夹的位置。

  

- 数据集：

  该项目的标准数据集如下所示：

  ```
  {"content": "类型#裙*材质#针织*颜色#纯色*风格#复古*风格#文艺*风格#简约*图案#格子*图案#纯色*图案#复古*裙型#背带裙*裙长#连衣裙*裙领型#半高领", "summary": "这款BRAND针织两件套连衣裙，简约的纯色半高领针织上衣，修饰着颈部线，尽显优雅气质。同时搭配叠穿起一条背带式的复古格纹裙，整体散发着一股怀旧的时髦魅力，很是文艺范。"}
  {"content": "类型#上衣*风格#嘻哈*图案#卡通*图案#印花*图案#撞色*衣样式#卫衣*衣款式#连帽", "summary": "嘻哈玩转童年，随时<UNK>，没错，出街还是要靠卫衣来装酷哦！时尚个性的连帽设计，率性有范还防风保暖。还有胸前撞色的卡通印花设计，靓丽抢眼更富有趣味性，加上前幅大容量又时尚美观的袋鼠兜，简直就是孩子耍帅装酷必备的利器。"}
  ......
  ```

  本项目用于训练的数据集如下所示：

  ```
  {
      "content": "试着提取下面日程信息中的时间, 地点和事件. 输出格式为起始时间:....;结束时间:....;地点:...;事件:.....;周期:.....;     欢迎投稿WISE2023会议！和Web Information Systems Engineering相关的论文都可以投，2023年10月25-27日在澳大利亚墨尔本开会，abstract和full paper的投稿截止时间都延期至6月20日，系统不会关 .当前时间:2023-4-4",
      "summary": "起始时间:2023-4-4; 结束时间:2023-6-20; 地点:无; 事件:WISE2023会议投稿; 周期:单次;"
  }
  {
      "content": "试着提取下面日程信息中的时间, 地点和事件. 输出格式为起始时间:....;结束时间:....;地点:...;事件:.....;周期:.....;     科大讯飞手气星火营Spark Camp学院推荐.时间：2023年8月15——8月25日.地点：安徽合肥. 科大讯飞除了全程费用报销之外我们学院可推荐两名学生参训 当前时间:2023-7-4",
      "summary": "起始时间:2023-8-15; 结束时间:2023-8-25; 地点:安徽合肥; 事件:学院推荐两名学生去科大讯飞手气星火营Spark Camp; 周期:单次;"
  }
  ......
  ```

  

- 训练时的报错：

  ```
  (glm2) [liwanyun@s2 ptuning]$ bash train.sh
  master_addr is only used for static rdzv_backend and when rdzv_endpoint is not specified.
  [E socket.cpp:860] [c10d] The client socket has timed out after 60s while trying to connect to (localhost, 29400).
  [E socket.cpp:860] [c10d] The client socket has timed out after 60s while trying to connect to (localhost, 29400).
  Traceback (most recent call last):
    File "/media/hnu/hnu2023/huangzhan/.conda/envs/glm2/lib/python3.10/site-packages/torch/distributed/elastic/rendezvous/c10d_rendezvous_backend.py", line 155, in _create_tcp_store
      store = TCPStore(
  TimeoutError: The client socket has timed out after 60s while trying to connect to (localhost, 29400).
  
  The above exception was the direct cause of the following exception:
  
  Traceback (most recent call last):
    File "/media/hnu/hnu2023/huangzhan/.conda/envs/glm2/bin/torchrun", line 33, in <module>
      sys.exit(load_entry_point('torch==2.0.1', 'console_scripts', 'torchrun')())
    File "/media/hnu/hnu2023/huangzhan/.conda/envs/glm2/lib/python3.10/site-packages/torch/distributed/elastic/multiprocessing/errors/__init__.py", line 346, in wrapper
      return f(*args, **kwargs)
    File "/media/hnu/hnu2023/huangzhan/.conda/envs/glm2/lib/python3.10/site-packages/torch/distributed/run.py", line 794, in main
      run(args)
    File "/media/hnu/hnu2023/huangzhan/.conda/envs/glm2/lib/python3.10/site-packages/torch/distributed/run.py", line 785, in run
      elastic_launch(
    File "/media/hnu/hnu2023/huangzhan/.conda/envs/glm2/lib/python3.10/site-packages/torch/distributed/launcher/api.py", line 134, in __call__
      return launch_agent(self._config, self._entrypoint, list(args))
    File "/media/hnu/hnu2023/huangzhan/.conda/envs/glm2/lib/python3.10/site-packages/torch/distributed/launcher/api.py", line 223, in launch_agent
      rdzv_handler=rdzv_registry.get_rendezvous_handler(rdzv_parameters),
    File "/media/hnu/hnu2023/huangzhan/.conda/envs/glm2/lib/python3.10/site-packages/torch/distributed/elastic/rendezvous/registry.py", line 65, in get_rendezvous_handler
      return handler_registry.create_handler(params)
    File "/media/hnu/hnu2023/huangzhan/.conda/envs/glm2/lib/python3.10/site-packages/torch/distributed/elastic/rendezvous/api.py", line 257, in create_handler
      handler = creator(params)
    File "/media/hnu/hnu2023/huangzhan/.conda/envs/glm2/lib/python3.10/site-packages/torch/distributed/elastic/rendezvous/registry.py", line 36, in _create_c10d_handler
      backend, store = create_backend(params)
    File "/media/hnu/hnu2023/huangzhan/.conda/envs/glm2/lib/python3.10/site-packages/torch/distributed/elastic/rendezvous/c10d_rendezvous_backend.py", line 250, in create_backend
      store = _create_tcp_store(params)
    File "/media/hnu/hnu2023/huangzhan/.conda/envs/glm2/lib/python3.10/site-packages/torch/distributed/elastic/rendezvous/c10d_rendezvous_backend.py", line 175, in _create_tcp_store
      raise RendezvousConnectionError(
  torch.distributed.elastic.rendezvous.api.RendezvousConnectionError: The connection to the C10d store has failed. See inner exception for details.
  ```

  

